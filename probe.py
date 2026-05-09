#!/usr/bin/env python3
"""
v2ray-prober: server-side fetcher + prober for the
MinaProNetVPN Android client's "Free V2Ray Servers" screen.

Runs the same fetch + probe pipeline the app does on-device, but
parallelised with asyncio and unconstrained by Android's binder
pool, so the whole 5000+ candidate list completes in ~1-2 minutes
instead of tens of minutes.

Output: v2ray-verified.json — a flat JSON array of objects matching
the PublicServer schema in
app/src/main/java/vpn/minapronet/com/eg/model/PublicServer.kt.
The client fetches that JSON in a single HTTP GET and shows every
server immediately, with no on-device probing.

Usage (locally):
    pip install -r requirements.txt
    python probe.py --output v2ray-verified.json

Usage (CI): see probe-workflow.yml.example.

License: MIT (this file and the surrounding tools/ directory only).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import time
import uuid as uuid_mod
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover — required, but we want a useful error
    _HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# Subscription sources — must stay in sync with API_SOURCES in
# PublicServersActivity.kt.  Hysteria2-bearing sources first, then V2Ray
# aggregators, then mixed-protocol grab bags.
# ---------------------------------------------------------------------------
API_SOURCES: List[str] = [
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription2",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list_raw.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub3.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub4.txt",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/mix",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/mix",
    "https://cdn.jsdelivr.net/gh/lagzian/SS-Collector@main/mix_base64.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/mix_base64.txt",
    "https://cdn.jsdelivr.net/gh/ts-sf/fly@master/v2",
    "https://raw.githubusercontent.com/ts-sf/fly/master/v2",
]

# How many concurrent probes to run.  Server-side has none of the netd
# binder constraints the on-device probe has, so we can be aggressive.
PROBE_CONCURRENCY = 80
PROBE_TCP_TIMEOUT = 2.5
PROBE_TLS_TIMEOUT = 3.5
SOURCE_FETCH_TIMEOUT = 30.0

# Stop probing once we have this many verified servers.
MAX_WORKING = 1500

# Country/flag heuristic for hosts that don't already carry a flag in
# their subscription name.  Built from the common ccTLDs that show up
# in subscription remarks; full GeoIP is out of scope for a CI script
# (would require shipping a database to every workflow run).
FLAG_BY_CC = {
    "US": "🇺🇸", "CA": "🇨🇦", "MX": "🇲🇽", "BR": "🇧🇷", "AR": "🇦🇷",
    "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱", "IT": "🇮🇹",
    "ES": "🇪🇸", "PL": "🇵🇱", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "DK": "🇩🇰", "CH": "🇨🇭", "AT": "🇦🇹", "IE": "🇮🇪", "RO": "🇷🇴",
    "BG": "🇧🇬", "PT": "🇵🇹", "BE": "🇧🇪", "GR": "🇬🇷", "CZ": "🇨🇿",
    "HU": "🇭🇺", "EE": "🇪🇪", "LT": "🇱🇹", "LV": "🇱🇻",
    "RU": "🇷🇺", "UA": "🇺🇦", "TR": "🇹🇷",
    "JP": "🇯🇵", "KR": "🇰🇷", "CN": "🇨🇳", "HK": "🇭🇰", "TW": "🇹🇼",
    "SG": "🇸🇬", "MY": "🇲🇾", "TH": "🇹🇭", "VN": "🇻🇳", "ID": "🇮🇩",
    "PH": "🇵🇭", "IN": "🇮🇳", "PK": "🇵🇰", "BD": "🇧🇩",
    "AU": "🇦🇺", "NZ": "🇳🇿",
    "AE": "🇦🇪", "SA": "🇸🇦", "EG": "🇪🇬", "MA": "🇲🇦", "DZ": "🇩🇿",
    "TN": "🇹🇳", "JO": "🇯🇴", "QA": "🇶🇦", "KW": "🇰🇼", "OM": "🇴🇲",
    "BH": "🇧🇭", "IQ": "🇮🇶", "LB": "🇱🇧", "ZA": "🇿🇦", "NG": "🇳🇬",
    "KE": "🇰🇪",
}

# Best-effort country guess from the subscription remark.  Most public
# subscriptions encode the country in the remark as a flag emoji or as
# the country name; this regex matches the latter.
COUNTRY_NAME_PATTERNS = [
    (re.compile(r"\b(United States|USA|US)\b", re.I), ("US", "United States", "🇺🇸")),
    (re.compile(r"\b(United Kingdom|UK|England|Britain)\b", re.I), ("GB", "United Kingdom", "🇬🇧")),
    (re.compile(r"\b(Germany|DE)\b", re.I), ("DE", "Germany", "🇩🇪")),
    (re.compile(r"\b(France|FR)\b", re.I), ("FR", "France", "🇫🇷")),
    (re.compile(r"\b(Netherlands|NL|Holland)\b", re.I), ("NL", "Netherlands", "🇳🇱")),
    (re.compile(r"\b(Hong Kong|HK)\b", re.I), ("HK", "Hong Kong", "🇭🇰")),
    (re.compile(r"\b(Singapore|SG)\b", re.I), ("SG", "Singapore", "🇸🇬")),
    (re.compile(r"\b(Japan|JP)\b", re.I), ("JP", "Japan", "🇯🇵")),
    (re.compile(r"\b(South Korea|Korea|KR)\b", re.I), ("KR", "South Korea", "🇰🇷")),
    (re.compile(r"\b(Canada|CA)\b", re.I), ("CA", "Canada", "🇨🇦")),
    (re.compile(r"\b(India|IN)\b", re.I), ("IN", "India", "🇮🇳")),
    (re.compile(r"\b(Russia|RU)\b", re.I), ("RU", "Russia", "🇷🇺")),
    (re.compile(r"\b(Turkey|TR)\b", re.I), ("TR", "Turkey", "🇹🇷")),
    (re.compile(r"\b(Australia|AU)\b", re.I), ("AU", "Australia", "🇦🇺")),
    (re.compile(r"\b(United Arab Emirates|UAE|AE)\b", re.I), ("AE", "United Arab Emirates", "🇦🇪")),
    (re.compile(r"\b(Egypt|EG)\b", re.I), ("EG", "Egypt", "🇪🇬")),
]

# Skip Israel-flagged servers to match the client-side filter.
SKIP_FLAGS = {"🇮🇱"}
SKIP_COUNTRY_NAMES = {"israel", "unknown"}


@dataclass
class PublicServer:
    """Exact JSON shape of vpn.minapronet.com.eg.model.PublicServer."""
    id: str = ""
    name: str = ""
    country: str = ""
    flag: str = "🌐"
    protocol: str = ""
    host: str = ""
    port: str = ""
    uuid: str = ""
    password: str = ""
    security: str = ""
    sni: str = ""
    flow: str = ""
    network: str = ""
    path: str = ""
    cipher: str = ""
    ping: str = "auto ping"
    status: str = "online"
    config_uri: str = ""
    remark: str = ""

    def as_dict(self) -> dict:
        # Gson reads "config_uri" as configUri via @SerializedName.  Keep
        # the underscored key in JSON to match the SerializedName values.
        return asdict(self)


# ---------------------------------------------------------------------------
# Subscription parsing.
# ---------------------------------------------------------------------------
def _b64decode(s: str) -> str:
    """Tolerant base64 decode that handles missing padding and URL-safe alphabet."""
    s = s.strip().replace("\n", "").replace("\r", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    s += "=" * pad
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except (binascii.Error, UnicodeDecodeError):
        return ""


def _looks_like_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 16:
        return False
    return re.match(r"^[A-Za-z0-9+/=_-]+$", s) is not None


def _guess_country_and_flag(remark: str) -> Tuple[str, str, str]:
    if not remark:
        return "", "Unknown", "🌐"
    # 1. Look for a flag emoji literal.
    for ch in remark:
        if 0x1F1E6 <= ord(ch) <= 0x1F1FF:
            # Two regional indicators in a row form the flag.
            idx = remark.index(ch)
            if idx + 1 < len(remark):
                ch2 = remark[idx + 1]
                if 0x1F1E6 <= ord(ch2) <= 0x1F1FF:
                    cc = chr(ord(ch) - 0x1F1E6 + ord("A")) + chr(ord(ch2) - 0x1F1E6 + ord("A"))
                    flag = ch + ch2
                    return cc, _country_for_cc(cc), flag
    # 2. Look for a known ccTLD or country word.
    for pattern, (cc, name, flag) in COUNTRY_NAME_PATTERNS:
        if pattern.search(remark):
            return cc, name, flag
    # 3. Single 2-letter token at start of remark, e.g. "US-Server-1".
    m = re.match(r"^\s*([A-Z]{2})[\W_]", remark)
    if m:
        cc = m.group(1)
        if cc in FLAG_BY_CC:
            return cc, _country_for_cc(cc), FLAG_BY_CC[cc]
    return "", "Unknown", "🌐"


def _country_for_cc(cc: str) -> str:
    # Reverse lookup the common-name map.
    common_names = {
        "US": "United States", "GB": "United Kingdom", "DE": "Germany",
        "FR": "France", "NL": "Netherlands", "HK": "Hong Kong",
        "SG": "Singapore", "JP": "Japan", "KR": "South Korea",
        "CA": "Canada", "IN": "India", "RU": "Russia", "TR": "Turkey",
        "AU": "Australia", "AE": "United Arab Emirates", "EG": "Egypt",
        "BR": "Brazil", "MX": "Mexico", "IT": "Italy", "ES": "Spain",
        "PL": "Poland", "SE": "Sweden", "FI": "Finland", "NO": "Norway",
        "DK": "Denmark", "CH": "Switzerland", "AT": "Austria",
        "IE": "Ireland", "RO": "Romania", "BG": "Bulgaria", "PT": "Portugal",
        "BE": "Belgium", "GR": "Greece", "CZ": "Czech Republic",
        "HU": "Hungary", "UA": "Ukraine", "CN": "China", "TW": "Taiwan",
        "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam", "ID": "Indonesia",
        "PH": "Philippines", "PK": "Pakistan", "BD": "Bangladesh",
        "NZ": "New Zealand", "SA": "Saudi Arabia", "MA": "Morocco",
        "DZ": "Algeria", "TN": "Tunisia", "JO": "Jordan", "QA": "Qatar",
        "KW": "Kuwait", "OM": "Oman", "BH": "Bahrain", "IQ": "Iraq",
        "LB": "Lebanon", "ZA": "South Africa", "NG": "Nigeria", "KE": "Kenya",
    }
    return common_names.get(cc, cc)


def parse_vmess(uri: str) -> Optional[PublicServer]:
    body = uri[len("vmess://"):]
    decoded = _b64decode(body)
    if not decoded.startswith("{"):
        return None
    try:
        cfg = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    host = str(cfg.get("add", "")).strip()
    port = str(cfg.get("port", "")).strip()
    if not host or not port:
        return None
    remark = str(cfg.get("ps", "")).strip()
    cc, country, flag = _guess_country_and_flag(remark)
    return PublicServer(
        name=remark or f"{host}:{port}",
        country=country,
        flag=flag,
        protocol="vmess",
        host=host,
        port=port,
        uuid=str(cfg.get("id", "")),
        security=str(cfg.get("tls", "")) or ("tls" if cfg.get("tls") else ""),
        sni=str(cfg.get("sni", "") or cfg.get("host", "")),
        network=str(cfg.get("net", "tcp")),
        path=str(cfg.get("path", "")),
        config_uri=uri,
        remark=remark,
    )


def parse_vless(uri: str) -> Optional[PublicServer]:
    parsed = urlparse(uri)
    if parsed.scheme != "vless" or not parsed.hostname or not parsed.port:
        return None
    qs = parse_qs(parsed.query or "")
    remark = unquote(parsed.fragment or "")
    cc, country, flag = _guess_country_and_flag(remark)
    return PublicServer(
        name=remark or f"{parsed.hostname}:{parsed.port}",
        country=country,
        flag=flag,
        protocol="vless",
        host=parsed.hostname,
        port=str(parsed.port),
        uuid=parsed.username or "",
        security=qs.get("security", [""])[0],
        sni=qs.get("sni", [parsed.hostname])[0],
        flow=qs.get("flow", [""])[0],
        network=qs.get("type", ["tcp"])[0],
        path=qs.get("path", [""])[0],
        config_uri=uri,
        remark=remark,
    )


def parse_trojan(uri: str) -> Optional[PublicServer]:
    parsed = urlparse(uri)
    if parsed.scheme != "trojan" or not parsed.hostname or not parsed.port:
        return None
    qs = parse_qs(parsed.query or "")
    remark = unquote(parsed.fragment or "")
    cc, country, flag = _guess_country_and_flag(remark)
    return PublicServer(
        name=remark or f"{parsed.hostname}:{parsed.port}",
        country=country,
        flag=flag,
        protocol="trojan",
        host=parsed.hostname,
        port=str(parsed.port),
        password=parsed.username or "",
        security="tls",
        sni=qs.get("sni", [parsed.hostname])[0],
        network=qs.get("type", ["tcp"])[0],
        path=qs.get("path", [""])[0],
        config_uri=uri,
        remark=remark,
    )


def parse_shadowsocks(uri: str) -> Optional[PublicServer]:
    # Two formats: ss://base64(method:pass@host:port)#remark
    #          or ss://base64(method:pass)@host:port#remark
    body = uri[len("ss://"):]
    if "#" in body:
        body, frag = body.split("#", 1)
        remark = unquote(frag)
    else:
        remark = ""
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        decoded_user = _b64decode(userinfo)
        if ":" not in decoded_user:
            return None
        method, password = decoded_user.split(":", 1)
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
    else:
        decoded = _b64decode(body)
        if "@" not in decoded or ":" not in decoded:
            return None
        creds, hostport = decoded.rsplit("@", 1)
        if ":" not in creds or ":" not in hostport:
            return None
        method, password = creds.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    if not host or not port.isdigit():
        return None
    cc, country, flag = _guess_country_and_flag(remark)
    return PublicServer(
        name=remark or f"{host}:{port}",
        country=country,
        flag=flag,
        protocol="ss",
        host=host,
        port=port,
        password=password,
        cipher=method,
        config_uri=uri,
        remark=remark,
    )


def parse_hysteria2(uri: str) -> Optional[PublicServer]:
    parsed = urlparse(uri)
    if parsed.scheme not in ("hysteria2", "hy2") or not parsed.hostname or not parsed.port:
        return None
    qs = parse_qs(parsed.query or "")
    remark = unquote(parsed.fragment or "")
    cc, country, flag = _guess_country_and_flag(remark)
    return PublicServer(
        name=remark or f"{parsed.hostname}:{parsed.port}",
        country=country,
        flag=flag,
        protocol="hysteria2",
        host=parsed.hostname,
        port=str(parsed.port),
        password=parsed.username or qs.get("password", [""])[0],
        security="tls",
        sni=qs.get("sni", [parsed.hostname])[0],
        network="udp",
        config_uri=uri,
        remark=remark,
    )


PARSERS = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "trojan://": parse_trojan,
    "ss://": parse_shadowsocks,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
}


def parse_one(line: str) -> Optional[PublicServer]:
    line = line.strip()
    if not line:
        return None
    for prefix, parser in PARSERS.items():
        if line.startswith(prefix):
            try:
                return parser(line)
            except Exception:
                return None
    return None


def parse_subscription(text: str) -> Iterable[PublicServer]:
    """A subscription body may be plain (one URI per line) or base64-encoded."""
    text = text.strip()
    if not text:
        return
    # If the whole body is base64, decode first.
    if _looks_like_base64(text) and "://" not in text[:64]:
        text = _b64decode(text)
    for line in text.splitlines():
        s = parse_one(line)
        if s is not None:
            yield s


# ---------------------------------------------------------------------------
# Probing.
#
# Why TCP+TLS isn't enough:
#   - TLS terminators (Nginx, Cloudflare, Caddy) accept the handshake even
#     when the V2Ray backend they're fronting is dead.  Probe says "fast
#     ping!", real client times out on the first VMess/VLESS packet.
#   - GFW / MENA carrier filters SYN-ACK then RST after handshake.
#   - Servers configured for a different protocol on that port still pass
#     TCP+TLS but reject the V2Ray handshake byte-for-byte.
#
# What V2RAY NG actually does (and we mirror here): for each protocol,
# send the real handshake bytes derived from the server's UUID/password,
# then check whether the server speaks the matching wire protocol back.
# A server that has an open port and a TLS cert but no actual V2Ray
# behind it RST's, returns HTTP 502, or sends an unrelated greeting —
# all of which we detect and discard.
# ---------------------------------------------------------------------------
def _needs_tls(server: PublicServer) -> bool:
    sec = (server.security or "").lower()
    proto = (server.protocol or "").lower()
    return sec in ("tls", "reality") or proto in ("trojan", "hysteria2")


# VMess AEAD constants.  The cmd_key suffix and the KDF salt are fixed
# in the protocol — see the v2fly VMess AEAD spec.
_VMESS_CMD_KEY_SUFFIX = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
_VMESS_KDF_KEY = b"VMess AEAD KDF"
_VMESS_AUTH_ID_SALT = b"AES Auth ID Encryption"


def _vmess_cmd_key(uuid_str: str) -> Optional[bytes]:
    try:
        uid = uuid_mod.UUID(uuid_str).bytes
    except (ValueError, AttributeError, TypeError):
        return None
    return hashlib.md5(uid + _VMESS_CMD_KEY_SUFFIX).digest()


def _vmess_kdf(key: bytes, *paths: bytes) -> bytes:
    """VMess AEAD KDF — HMAC-SHA256 chain.  See v2fly docs."""
    result = hmac.new(_VMESS_KDF_KEY, key, hashlib.sha256).digest()
    for path in paths:
        result = hmac.new(result, path, hashlib.sha256).digest()
    return result


def _vmess_create_auth_id(cmd_key: bytes) -> bytes:
    """Create a 16-byte VMess AEAD AuthID.

    Layout: timestamp (8 BE) || random (4) || crc32 (4 BE) — encrypted
    with AES-128-ECB using KDF(cmd_key, "AES Auth ID Encryption")[:16].
    A real VMess server decrypts this, validates the CRC, and waits for
    the encrypted command section.  A wrong UUID / non-VMess server
    fails the CRC check and either RSTs or sends an HTTP error.
    """
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography package is required for VMess probe")
    plaintext = struct.pack(">Q", int(time.time())) + os.urandom(4)
    plaintext += struct.pack(">I", binascii.crc32(plaintext) & 0xFFFFFFFF)
    aes_key = _vmess_kdf(cmd_key, _VMESS_AUTH_ID_SALT)[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


async def _drain_briefly(reader: asyncio.StreamReader, timeout: float) -> Tuple[bool, bytes]:
    """Wait for unsolicited data from the peer.

    Returns (got_data_or_eof, data).  Real V2Ray protocols stay silent
    after the TLS handshake until the client sends the protocol header,
    so any data here is a strong signal the server isn't V2Ray.  EOF
    means the server already closed the connection — also bad.
    """
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        return True, data  # data may be empty bytes (EOF)
    except asyncio.TimeoutError:
        return False, b""
    except (OSError, ssl.SSLError, ConnectionError):
        return True, b""  # treat connection error as "got something" (= bad)


async def _vless_probe(reader, writer, server: PublicServer) -> bool:
    """Real VLESS handshake probe — send the actual client header with the
    server's UUID and a CONNECT request to a benign target, expect the
    server to respond with a valid VLESS response header.
    """
    if not server.uuid:
        # Without a UUID we can't speak VLESS — fall back to silence check.
        got_data, _ = await _drain_briefly(reader, 0.4)
        return not got_data
    try:
        uuid_bytes = uuid_mod.UUID(server.uuid).bytes
    except (ValueError, AttributeError, TypeError):
        return False
    # VLESS request header:
    #   version 0x00 (1) | UUID (16) | addons_len 0x00 (1) | cmd 0x01 CONNECT (1) |
    #   port (2 BE) | atyp 0x01 IPv4 (1) | addr 1.1.1.1 (4)
    header = (
        b"\x00" + uuid_bytes + b"\x00" + b"\x01"
        + struct.pack(">H", 80)
        + b"\x01" + b"\x01\x01\x01\x01"
    )
    payload = b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: probe\r\n\r\n"
    try:
        writer.write(header + payload)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=2.5)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    # Real VLESS response begins with [version 0x00][addons_length 0x00],
    # followed by the tunneled response (here, HTTP from 1.1.1.1).
    return len(response) >= 2 and response[0] == 0x00 and response[1] == 0x00


async def _vmess_probe(reader, writer, server: PublicServer) -> bool:
    """Real VMess AEAD probe — derive the auth ID from the server's UUID
    and send it.  A real VMess server with a matching UUID will silently
    wait for the encrypted command section; everything else (wrong UUID,
    not-VMess, dead backend) sends back HTTP error data or RSTs the
    connection within a few hundred ms.
    """
    cmd_key = _vmess_cmd_key(server.uuid)
    if cmd_key is None:
        # Bad UUID — can't probe properly, fall back to silence check.
        got_data, _ = await _drain_briefly(reader, 0.5)
        return not got_data
    try:
        auth_id = _vmess_create_auth_id(cmd_key)
        writer.write(auth_id)
        await writer.drain()
    except (OSError, ssl.SSLError, RuntimeError):
        return False
    # Real VMess: stays silent waiting for the rest of the encrypted
    # request (length + cmd section).  Anything else: HTTP/2 SETTINGS,
    # 502 Bad Gateway, 400 Bad Request, RST...
    got_data, data = await _drain_briefly(reader, 0.6)
    if not got_data:
        return True
    # If we got TLS application data that looks like HTTP, definitely fail.
    if data.startswith(b"HTTP/") or data[:2] == b"\x00\x00" and len(data) >= 24:
        return False
    # Any other unsolicited data is also suspicious for VMess.
    return False


async def _trojan_probe(reader, writer, server: PublicServer) -> bool:
    """Real Trojan handshake probe — send SHA224(password) hex + a CONNECT
    request to 1.1.1.1:80, then check the response.

    Trojan's "fallback to web server" behaviour means a wrong password
    proxies to the configured fallback site and returns its HTML default
    page; a right password forwards to 1.1.1.1 which returns either a
    Cloudflare 301-to-HTTPS or a quick HTTP response.  Distinguishing
    right-from-wrong-password is tricky, so we instead use this probe
    to confirm the server is actually doing TLS-then-Trojan-or-fallback
    (vs. a dead reverse proxy which would just RST or 502).
    """
    if not server.password:
        got_data, _ = await _drain_briefly(reader, 0.4)
        return not got_data
    try:
        pw_hash = hashlib.sha224(server.password.encode("utf-8")).hexdigest().encode("ascii")
    except Exception:
        return False
    # Trojan request: SHA224(password) hex || CRLF || CMD 0x01 CONNECT ||
    # ATYP 0x01 IPv4 || addr 1.1.1.1 || port 80 (BE) || CRLF || payload
    req = (
        pw_hash + b"\r\n"
        + b"\x01"
        + b"\x01" + b"\x01\x01\x01\x01" + struct.pack(">H", 80)
        + b"\r\n"
        + b"GET / HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: probe\r\n\r\n"
    )
    try:
        writer.write(req)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=2.5)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    # Either "real Trojan + right password forwards to 1.1.1.1" or
    # "real Trojan + wrong password falls back to web server" returns
    # HTTP-shaped data.  A dead backend behind TLS returns nothing or
    # an SSL error — already caught above.
    if not response:
        return False
    return response.startswith(b"HTTP/") or b"<html" in response[:512].lower()


async def probe(server: PublicServer) -> Optional[int]:
    """Returns ping in ms, or None if the server failed the probe.

    Per-protocol handshake check, NOT just TCP+TLS — see module-level
    docstring for why TCP+TLS produced false positives that the user's
    real V2Ray client (V2RAY NG) caught.
    """
    try:
        port = int(server.port)
    except ValueError:
        return None
    if not (1 <= port <= 65535) or not server.host:
        return None

    proto = (server.protocol or "").lower()
    needs_tls = _needs_tls(server)
    start = time.monotonic()

    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    try:
        # Step 1: open the connection (with TLS if required).  We open
        # the TLS connection in one shot via the ssl=ctx parameter
        # rather than upgrading after the fact, because asyncio's
        # start_tls is finicky across Python versions and we need the
        # post-handshake reader/writer to do the protocol probe below.
        if needs_tls:
            sni = server.sni or server.host
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server.host, port, ssl=ctx, server_hostname=sni),
                    timeout=PROBE_TCP_TIMEOUT + PROBE_TLS_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError, ssl.SSLError):
                return None
        else:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server.host, port),
                    timeout=PROBE_TCP_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError):
                return None

        # Step 2: protocol-specific handshake.  Each branch sends the
        # real wire bytes that V2RAY NG would send in production, then
        # checks the server's response matches the protocol spec.
        try:
            if proto == "vless":
                ok = await _vless_probe(reader, writer, server)
            elif proto == "vmess":
                ok = await _vmess_probe(reader, writer, server)
            elif proto == "trojan":
                ok = await _trojan_probe(reader, writer, server)
            else:
                # Shadowsocks and unknown protocols: the most we can do
                # without implementing a full cipher is a "the server
                # stays silent like a real proxy would" check.  This
                # still catches HTTP fallthroughs, default Nginx pages,
                # and dead backends behind TLS terminators.
                got_data, _ = await _drain_briefly(reader, 0.4)
                ok = not got_data
        except Exception:
            ok = False

        if not ok:
            return None
        return max(1, int((time.monotonic() - start) * 1000))
    except Exception:
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Pipeline.
# ---------------------------------------------------------------------------
async def fetch_source(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=SOURCE_FETCH_TIMEOUT)) as resp:
            if resp.status != 200:
                logging.warning("source HTTP %s: %s", resp.status, url)
                return ""
            return await resp.text(errors="replace")
    except Exception as e:
        logging.warning("source failed: %s — %s", url, e)
        return ""


async def main_async(output_path: str, limit: int) -> int:
    logging.info("starting prober — limit=%d, concurrency=%d", limit, PROBE_CONCURRENCY)
    headers = {"User-Agent": "Mozilla/5.0"}
    seen: Set[str] = set()
    candidates: List[PublicServer] = []

    async with aiohttp.ClientSession(headers=headers) as session:
        for url in API_SOURCES:
            text = await fetch_source(session, url)
            if not text:
                continue
            for server in parse_subscription(text):
                if not server.host or not server.port.isdigit():
                    continue
                portn = int(server.port)
                if not (1 <= portn <= 65535):
                    continue
                # Drop private / loopback / unspecified addresses.
                if server.host.startswith(("127.", "10.", "192.168.", "0.")) or \
                   server.host == "localhost" or "example" in server.host:
                    continue
                if server.flag in SKIP_FLAGS:
                    continue
                if server.country.lower() in SKIP_COUNTRY_NAMES:
                    continue
                key = f"{server.host}:{server.port}"
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(server)

    logging.info("parsed %d unique candidates from %d sources", len(candidates), len(API_SOURCES))

    # Probe with bounded concurrency.
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    verified: List[PublicServer] = []

    async def probe_one(server: PublicServer) -> None:
        if len(verified) >= limit:
            return
        async with sem:
            if len(verified) >= limit:
                return
            ping = await probe(server)
            if ping is not None:
                server.ping = f"{ping}ms"
                server.status = "online"
                verified.append(server)
                if len(verified) % 100 == 0:
                    logging.info("progress: %d verified / %d probed",
                                 len(verified), len(candidates))

    await asyncio.gather(*(probe_one(s) for s in candidates))

    verified = verified[:limit]
    # Sort by ping ascending so the fastest servers show first in the
    # client list before any user-side sort-by-name / sort-by-ping pass.
    verified.sort(key=lambda s: int(s.ping.replace("ms", "")) if s.ping.endswith("ms") else 999)

    payload = [s.as_dict() for s in verified]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    logging.info("wrote %d verified servers to %s", len(payload), output_path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--output", default="v2ray-verified.json",
                        help="output JSON path (default: v2ray-verified.json)")
    parser.add_argument("--limit", type=int, default=MAX_WORKING,
                        help="maximum verified servers to keep (default: %d)" % MAX_WORKING)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return asyncio.run(main_async(args.output, args.limit))


if __name__ == "__main__":
    sys.exit(main())
