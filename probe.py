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
import shutil
import socket
import ssl
import struct
import sys
import tempfile
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
    # ---------------------------------------------------------------------------
    # w1770946466/Auto_proxy — Hysteria2 + mixed (always first)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription2",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription3",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription4",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription5",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription6",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription7",

    # ---------------------------------------------------------------------------
    # peasoft/NoMoreWalls
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list_raw.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.txt",

    # ---------------------------------------------------------------------------
    # roosterkid/openproxylist
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/TROJAN_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/TROJAN_RAW.txt",
    "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist@main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",

    # ---------------------------------------------------------------------------
    # mahdibland/V2RayAggregator
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://cdn.jsdelivr.net/gh/mahdibland/ShadowsocksAggregator@master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://cdn.jsdelivr.net/gh/mahdibland/ShadowsocksAggregator@master/EternityAir",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir",

    # ---------------------------------------------------------------------------
    # mfuu/v2ray
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/clash.yaml",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",

    # ---------------------------------------------------------------------------
    # barry-far/V2ray-Configs — Sub1..Sub12 + All_Configs
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub3.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub4.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub5.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub6.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub6.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub7.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub7.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Sub8.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub8.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_base64_Sub.txt",

    # ---------------------------------------------------------------------------
    # yebekhe/TelegramV2rayCollector
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/mix",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/mix",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/vmess",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/vmess",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/vless",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/trojan",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/trojan",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/base64/ss",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/ss",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramV2rayCollector@main/sub/plain/mix",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/plain/mix",

    # ---------------------------------------------------------------------------
    # yebekhe/TelegramProxies
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/yebekhe/TelegramProxies/main/sub/base64/mix",
    "https://cdn.jsdelivr.net/gh/yebekhe/TelegramProxies@main/sub/base64/mix",

    # ---------------------------------------------------------------------------
    # lagzian/SS-Collector
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/lagzian/SS-Collector@main/mix_base64.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/mix_base64.txt",
    "https://cdn.jsdelivr.net/gh/lagzian/SS-Collector@main/SS_B64.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS_B64.txt",
    "https://cdn.jsdelivr.net/gh/lagzian/TVC@main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/lagzian/TVC/main/subscriptions/xray/base64/mix",

    # ---------------------------------------------------------------------------
    # ts-sf/fly
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/ts-sf/fly@master/v2",
    "https://raw.githubusercontent.com/ts-sf/fly/master/v2",

    # ---------------------------------------------------------------------------
    # freefq/free — large Chinese aggregator
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/freefq/free@master/v2",
    "https://raw.githubusercontent.com/freefq/free/master/v2",

    # ---------------------------------------------------------------------------
    # aiboboxx/v2rayfree
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/aiboboxx/v2rayfree@main/v2",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",

    # ---------------------------------------------------------------------------
    # Pawdroid/Free-servers
    # ---------------------------------------------------------------------------
    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",

    # ---------------------------------------------------------------------------
    # ermaozi/get_subscribe
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/ermaozi01/free_clash_vpn@main/subscribe/v2ray.txt",

    # ---------------------------------------------------------------------------
    # tbbatbb/vpn_list — daily updated
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",
    "https://cdn.jsdelivr.net/gh/tbbatbb/Proxy@master/dist/v2ray.config.txt",

    # ---------------------------------------------------------------------------
    # wrfree/v2free
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/wrfree/free/main/v2",
    "https://cdn.jsdelivr.net/gh/wrfree/free@main/v2",

    # ---------------------------------------------------------------------------
    # vveg26/v2rayNG-config
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/vveg26/get_proxy/main/speed/all",
    "https://cdn.jsdelivr.net/gh/vveg26/get_proxy@main/speed/all",

    # ---------------------------------------------------------------------------
    # Bardiafa/Free
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/Bardiafa/Free-V2ray-List/main/All_Configs_Sub.txt",
    "https://cdn.jsdelivr.net/gh/Bardiafa/Free-V2ray-List@main/All_Configs_Sub.txt",

    # ---------------------------------------------------------------------------
    # LalatinaHub/Married-lady
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/main/result/api/1/all",
    "https://cdn.jsdelivr.net/gh/LalatinaHub/Mineral@main/result/api/1/all",

    # ---------------------------------------------------------------------------
    # mheidari98/proxy-list
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",
    "https://cdn.jsdelivr.net/gh/mheidari98/.proxy@main/all",

    # ---------------------------------------------------------------------------
    # HideMyIP / tgcf-daily aggregators
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/collective/base64/mix",
    "https://cdn.jsdelivr.net/gh/soroushmirzaei/telegram-configs-collector@main/subscribe/collective/base64/mix",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/protocols/vmess",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/protocols/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscribe/protocols/shadowsocks",

    # ---------------------------------------------------------------------------
    # ALIILAPRO/v2ray-config
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/ALIILAPRO/v2ray-config/main/sub.txt",
    "https://cdn.jsdelivr.net/gh/ALIILAPRO/v2ray-config@main/sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2ray-config/main/server.txt",

    # ---------------------------------------------------------------------------
    # Surfboardv2ray aggregators
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
    "https://cdn.jsdelivr.net/gh/IranianCypherpunks/sub@main/config",

    # ---------------------------------------------------------------------------
    # itsyebekhe/HiN-VPN
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
    "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/base64/mix",
    "https://cdn.jsdelivr.net/gh/itsyebekhe/HiN-VPN@main/subscription/base64/mix",

    # ---------------------------------------------------------------------------
    # Everyday-VPN / Iranian sources
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://cdn.jsdelivr.net/gh/MrMohebi/xray-proxy-grabber-telegram@master/collected-proxies/row-url/all.txt",

    # ---------------------------------------------------------------------------
    # Surfboard/Clash meta mixed sources
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/Rayan428/v2config/main/sub",
    "https://cdn.jsdelivr.net/gh/Rayan428/v2config@main/sub",

    # ---------------------------------------------------------------------------
    # PolloLoco / XTLS sources
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/poloskei/poloskei/refs/heads/main/files/output.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vmess",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/trojan",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/ss",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/all3",
    "https://cdn.jsdelivr.net/gh/Leon406/SubCrawler@master/sub/share/all3",

    # ---------------------------------------------------------------------------
    # tachyondevel / multi-protocol
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/tachyondevel/open-tunnel/main/sub",
    "https://cdn.jsdelivr.net/gh/tachyondevel/open-tunnel@main/sub",

    # ---------------------------------------------------------------------------
    # Proxy-Store / large mixed
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json",

    # ---------------------------------------------------------------------------
    # 0xkuj / mixed
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/0xkuj/V2ray/main/V2ray",
    "https://cdn.jsdelivr.net/gh/0xkuj/V2ray@main/V2ray",

    # ---------------------------------------------------------------------------
    # manuGMG/free-v2ray
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/manuGMG/proxy-365/main/VMESS.txt",

    # ---------------------------------------------------------------------------
    # vmessprotocol / daily update
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/vmessprotocol/subscribe/main/vmess.txt",
    "https://cdn.jsdelivr.net/gh/vmessprotocol/subscribe@main/vmess.txt",

    # ---------------------------------------------------------------------------
    # Surfboard-ready ClashMeta aggregators (plain URI fallback)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/coldwater-10/V2Hub/main/merge",
    "https://cdn.jsdelivr.net/gh/coldwater-10/V2Hub@main/merge",
    "https://raw.githubusercontent.com/coldwater-10/V2Hub2/main/merge",
    "https://cdn.jsdelivr.net/gh/coldwater-10/V2Hub2@main/merge",
    "https://raw.githubusercontent.com/coldwater-10/V2Hub3/main/merge",
    "https://cdn.jsdelivr.net/gh/coldwater-10/V2Hub3@main/merge",

    # ---------------------------------------------------------------------------
    # SoliSpirit (high-refresh Iranian aggregator)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/all_configs.txt",

    # ---------------------------------------------------------------------------
    # AryanGold / GFW bypass
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/AryanGold/temp_config/main/Splitter_Sub.txt",
    "https://cdn.jsdelivr.net/gh/AryanGold/temp_config@main/Splitter_Sub.txt",

    # ---------------------------------------------------------------------------
    # hkaa0 / tipray
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/hkaa0/permalink/main/proxy/V2ray",
    "https://cdn.jsdelivr.net/gh/hkaa0/permalink@main/proxy/V2ray",

    # ---------------------------------------------------------------------------
    # rxzyx / v2rayfree
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/rxzyx/V2RayFreePro/main/Vl.txt",
    "https://cdn.jsdelivr.net/gh/rxzyx/V2RayFreePro@main/Vl.txt",

    # ---------------------------------------------------------------------------
    # Surfing-Hub / Aggregation
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/splitted/mixed",
    "https://cdn.jsdelivr.net/gh/Surfboardv2ray/TGParse@main/python/splitted/mixed",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/output.txt",
    "https://cdn.jsdelivr.net/gh/Surfboardv2ray/Proxy-sorter@main/output.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/master/Eternity.txt",
    "https://cdn.jsdelivr.net/gh/Surfboardv2ray/v2ray-worker-sub@master/Eternity.txt",

    # ---------------------------------------------------------------------------
    # HexaSurface / speed-tested
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/HexaSurface/V2RAY_URL_Filter/main/filtered_urls.txt",

    # ---------------------------------------------------------------------------
    # 4everProxy / TG-sourced
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/4ever-freedom/4EverFreedom/main/TG_sub",
    "https://cdn.jsdelivr.net/gh/4ever-freedom/4EverFreedom@main/TG_sub",

    # ---------------------------------------------------------------------------
    # MatinGhasemi / VLESS focus
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/MatinGhasemi/vless/main/vless",
    "https://cdn.jsdelivr.net/gh/MatinGhasemi/vless@main/vless",

    # ---------------------------------------------------------------------------
    # kaoxindalao / speed-tested Chinese
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/kaoxindalao/v2raycheshi/main/v2raycheshi",
    "https://cdn.jsdelivr.net/gh/kaoxindalao/v2raycheshi@main/v2raycheshi",

    # ---------------------------------------------------------------------------
    # Misaka-blog aggregators
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/misaka-blog/chromego_merge/main/sub/merged_proxies_new.yaml",
    "https://cdn.jsdelivr.net/gh/misaka-blog/chromego_merge@main/sub/merged_proxies_new.yaml",

    # ---------------------------------------------------------------------------
    # ZywChannel / TG collector
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/ZywChannel/free/main/sub",
    "https://cdn.jsdelivr.net/gh/ZywChannel/free@main/sub",

    # ---------------------------------------------------------------------------
    # SGNOOB / sub
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/SGNOOB/config/main/sub/sub_merge_base64.txt",
    "https://cdn.jsdelivr.net/gh/SGNOOB/config@main/sub/sub_merge_base64.txt",

    # ---------------------------------------------------------------------------
    # codingbox / daily
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/codingbox/Free-Node-Merge/main/node.txt",
    "https://cdn.jsdelivr.net/gh/codingbox/Free-Node-Merge@main/node.txt",

    # ---------------------------------------------------------------------------
    # PassiveNodes / large dump
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://cdn.jsdelivr.net/gh/awesome-vpn/awesome-vpn@master/all",

    # ---------------------------------------------------------------------------
    # xrayfree / updated frequently
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/xrayfree/free-ssr-ss-v2ray-vpn-clash/main/trial/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/xrayfree/free-ssr-ss-v2ray-vpn-clash@main/trial/v2ray.txt",

    # ---------------------------------------------------------------------------
    # TelegramFreeProxy / dedicated Telegram collector
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/imohammadkhalili/V2RAY/main/Mkhalili",
    "https://cdn.jsdelivr.net/gh/imohammadkhalili/V2RAY@main/Mkhalili",

    # ---------------------------------------------------------------------------
    # AzadNet (Iranian GFW circumvention)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/AzadNet/v2ray-configs/main/sub/all",
    "https://cdn.jsdelivr.net/gh/AzadNet/v2ray-configs@main/sub/all",

    # ---------------------------------------------------------------------------
    # v2rayse / consolidated
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/v2rayse/node-list/main/week.txt",
    "https://cdn.jsdelivr.net/gh/v2rayse/node-list@main/week.txt",

    # ---------------------------------------------------------------------------
    # FVPN / multi-protocol
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/FQrabbit/SSTap-Rule/master/sub/all",

    # ---------------------------------------------------------------------------
    # tgfreeproxy + Telegram channel mirrors
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/amirblum/v2ray/main/amirblum",
    "https://cdn.jsdelivr.net/gh/amirblum/v2ray@main/amirblum",

    # ---------------------------------------------------------------------------
    # resasanian / verified daily
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/resasanian/Mirza/main/best.txt",
    "https://cdn.jsdelivr.net/gh/resasanian/Mirza@main/best.txt",
    "https://raw.githubusercontent.com/resasanian/Mirza/main/sub",
    "https://cdn.jsdelivr.net/gh/resasanian/Mirza@main/sub",

    # ---------------------------------------------------------------------------
    # MhdiTaheri / V2nodeJS
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/MhdiTaheri/V2nodeJS/main/v2",
    "https://cdn.jsdelivr.net/gh/MhdiTaheri/V2nodeJS@main/v2",

    # ---------------------------------------------------------------------------
    # AliDehbansiahkarbon — VLESS / REALITY focus
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/AliDehbansiahkarbon/ChatGPTVirus/main/sub/subscribe_base64.txt",
    "https://cdn.jsdelivr.net/gh/AliDehbansiahkarbon/ChatGPTVirus@main/sub/subscribe_base64.txt",

    # ---------------------------------------------------------------------------
    # prxyshare (daily cron)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/prxyshare/prxyshare/main/vmix",
    "https://cdn.jsdelivr.net/gh/prxyshare/prxyshare@main/vmix",

    # ---------------------------------------------------------------------------
    # a2470981985 / free nodes
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/a2470981985/get_proxy/main/clash.yaml",

    # ---------------------------------------------------------------------------
    # IP-ProxyTool / nodes
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/ip-scanner/cloudflare/main/sub.txt",
    "https://cdn.jsdelivr.net/gh/ip-scanner/cloudflare@main/sub.txt",

    # ---------------------------------------------------------------------------
    # HexaHunterVPN (fast-probe output)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/HexaHunterVPN/FreeVPNsList/main/v2ray",
    "https://cdn.jsdelivr.net/gh/HexaHunterVPN/FreeVPNsList@main/v2ray",

    # ---------------------------------------------------------------------------
    # GreenFishStudio / Iran-optimised
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/GreenFishStudio/GreenFish/master/Subscription/GreenFishYYDS",
    "https://cdn.jsdelivr.net/gh/GreenFishStudio/GreenFish@master/Subscription/GreenFishYYDS",

    # ---------------------------------------------------------------------------
    # itsyebekhe / xray-reality
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/sub",
    "https://cdn.jsdelivr.net/gh/itsyebekhe/PSG@main/sub",

    # ---------------------------------------------------------------------------
    # proxypool / online services (raw URI endpoints)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/all_proxies.txt",
    "https://cdn.jsdelivr.net/gh/vxiaov/free_proxies@main/all_proxies.txt",

    # ---------------------------------------------------------------------------
    # Navier-Stokes / wulabing aggregator
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/info",

    # ---------------------------------------------------------------------------
    # Alvin9999 (large Chinese share)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/Alvin9999/new-pac/master/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/Alvin9999/new-pac@master/v2ray.txt",

    # ---------------------------------------------------------------------------
    # xiaoqi7788 / daily
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/xiaoqi7788/v2ray-nodes/main/nodes",
    "https://cdn.jsdelivr.net/gh/xiaoqi7788/v2ray-nodes@main/nodes",

    # ---------------------------------------------------------------------------
    # NodeList.top mirror (no JS; direct text)
    # ---------------------------------------------------------------------------
    "https://raw.githubusercontent.com/NodeList-top/NodeList/master/list/v2ray.txt",
    "https://cdn.jsdelivr.net/gh/NodeList-top/NodeList@master/list/v2ray.txt",
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


async def _ws_upgrade_probe(
    reader, writer, host_header: str, path: str, timeout: float = 2.0
) -> bool:
    """Send a WebSocket Upgrade request to the configured path and verify
    the server responds with HTTP/1.1 101 Switching Protocols.

    Catches the most common WS-transport false positive: a Cloudflare
    tunnel URL whose backend has gone down but whose edge still terminates
    TLS.  A pure silence check passes those because Cloudflare's edge
    waits for an HTTP request and stays quiet for the probe window;
    a real Upgrade request to that dead tunnel returns 503 / 404 / a
    Cloudflare error page within ~1s, which we then reject.
    """
    if not path:
        path = "/"
    elif not path.startswith("/"):
        path = "/" + path
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    ).encode("ascii")
    try:
        writer.write(request)
        await writer.drain()
        head = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    if not head:
        return False
    # Status line: "HTTP/1.1 101 Switching Protocols"
    return b" 101 " in head[:64] or b"HTTP/1.1 101" in head[:64]


def _is_ws_transport(server: PublicServer) -> bool:
    return (server.network or "").lower() == "ws"


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
            # WebSocket-transport servers (the dominant choice for
            # Cloudflare-tunnelled deployments) need a real Upgrade
            # request first.  A pure protocol probe under WS would
            # fail because the server expects WS frames, not raw
            # protocol bytes — and a pure silence check passes any
            # Cloudflare tunnel even when the backend is dead, because
            # Cloudflare's edge stays quiet until the user sends an
            # HTTP request.  The Upgrade probe sends one, and rejects
            # everything that doesn't reply 101 Switching Protocols
            # (dead tunnel → 503, wrong path → 404, default site → 200,
            # bad gateway → 502, etc.).
            if _is_ws_transport(server):
                ws_host = server.sni or server.host
                ok = await _ws_upgrade_probe(reader, writer, ws_host, server.path)
            elif proto == "vless":
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
# Stage 2: real V2Ray engine verification via xray-core.
#
# The Stage 1 probe (TCP + TLS + WebSocket Upgrade + protocol-handshake
# heuristics) is fast but imperfect — it can still pass servers whose
# inner V2Ray protocol is dead even when the outer transport is alive
# (a Cloudflare tunnel that responds 101 to the WS Upgrade but whose
# backend died in the last few seconds, a UUID that was rotated server-
# side, etc.).  V2RAY NG catches these because it uses xray-core / v2ray-
# core to run the full stack on the test path and only reports success
# when an actual HTTP request can travel through the tunnel.
#
# Stage 2 mirrors that exactly: for each Stage 1 survivor, generate a
# minimal xray config that uses the candidate as outbound and a SOCKS
# inbound on a fresh local port, start the xray subprocess, then try
# `curl --socks5-hostname` to a connectivity-check URL.  Only candidates
# that return HTTP 204 (Google) or 200 (Cloudflare) within the timeout
# are accepted into the verified list.  Anything else — connection
# refused, TLS error, WS-101-but-dead-V2Ray-backend, wrong UUID, wrong
# password, wrong path, server overloaded — fails the test silently.
#
# This is the same gold-standard test V2RAY NG runs.  If xray isn't on
# PATH, we log a warning and emit Stage 1 results unchanged so the
# workflow still produces SOMETHING; for production accuracy the
# workflow should install xray-core (see probe-workflow.yml.example).
# ---------------------------------------------------------------------------
XRAY_BINARY = shutil.which("xray") or shutil.which("v2ray")
XRAY_TEST_TARGETS: List[str] = [
    # Google's connectivity check (returns 204 No Content).  Reachable
    # from every CI runner region we've seen.
    "https://www.gstatic.com/generate_204",
    # Cloudflare's diagnostic (returns 200 with a small body).  Different
    # IP space / TLS chain than Google so a regional block on one doesn't
    # invalidate every probe.
    "https://www.cloudflare.com/cdn-cgi/trace",
]
XRAY_STARTUP_DELAY_S = 0.5
XRAY_TEST_TIMEOUT_S = 6.0
XRAY_OVERALL_TIMEOUT_S = 10.0
# Independent concurrency cap for Stage 2 — each xray instance is its
# own subprocess (~10-20 MB RAM, listening on a SOCKS port), so we run
# fewer in parallel than Stage 1.  GitHub Actions runners are 2-vCPU,
# 7 GB; 25 concurrent xray instances is comfortable, leaves headroom
# for the curl side-by-side and never trips the Linux ephemeral-port
# pressure limit.
XRAY_CONCURRENCY = 25


def _find_free_port() -> int:
    """Bind to a random ephemeral port and immediately release it,
    returning the port number.  Subject to a TOCTOU race if another
    process binds the same port before xray starts, but the worst-case
    outcome is one probe failing — which we treat as "not working" anyway.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _xray_stream_settings(server: PublicServer) -> dict:
    """Build the streamSettings block for an xray outbound matching the
    server's transport and security mode.
    """
    network = (server.network or "tcp").lower()
    security = (server.security or "none").lower()

    settings: dict = {
        "network": network if network in ("tcp", "ws", "grpc", "h2", "kcp", "quic") else "tcp",
        "security": security if security in ("tls", "reality") else "none",
    }

    if security == "tls":
        settings["tlsSettings"] = {
            "serverName": server.sni or server.host,
            "allowInsecure": True,
            "alpn": ["h2", "http/1.1"],
        }
    elif security == "reality":
        # Reality requires publicKey and shortId, which the subscription
        # URI doesn't always carry.  Without them the handshake will
        # fail.  Caller (xray_probe) refuses to test Reality servers
        # when the fields are missing.
        settings["realitySettings"] = {
            "serverName": server.sni or server.host,
            "fingerprint": "chrome",
            "publicKey": "",
            "shortId": "",
        }

    if network == "ws":
        path = server.path if server.path.startswith("/") else f"/{server.path or ''}"
        if not path:
            path = "/"
        settings["wsSettings"] = {
            "path": path,
            "headers": {"Host": server.sni or server.host},
        }
    elif network == "grpc":
        settings["grpcSettings"] = {
            "serviceName": (server.path or "").lstrip("/"),
            "multiMode": False,
        }
    elif network == "h2":
        settings["httpSettings"] = {
            "host": [server.sni or server.host],
            "path": server.path or "/",
        }

    return settings


def _xray_config(server: PublicServer, socks_port: int) -> Optional[dict]:
    """Generate a minimal xray config for the given server, or None if
    the server has missing fields the engine can't tolerate.
    """
    proto = (server.protocol or "").lower()
    try:
        port_int = int(server.port)
    except ValueError:
        return None
    if not (1 <= port_int <= 65535):
        return None

    inbound = {
        "port": socks_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False, "ip": "127.0.0.1"},
        "tag": "socks-in",
    }

    stream = _xray_stream_settings(server)

    if proto == "vless":
        if not server.uuid:
            return None
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server.host,
                    "port": port_int,
                    "users": [{
                        "id": server.uuid,
                        "encryption": "none",
                        "flow": server.flow or "",
                    }],
                }],
            },
            "streamSettings": stream,
            "tag": "out",
        }
    elif proto == "vmess":
        if not server.uuid:
            return None
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server.host,
                    "port": port_int,
                    "users": [{
                        "id": server.uuid,
                        "alterId": 0,
                        "security": (server.cipher or "auto").lower(),
                    }],
                }],
            },
            "streamSettings": stream,
            "tag": "out",
        }
    elif proto == "trojan":
        if not server.password:
            return None
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server.host,
                    "port": port_int,
                    "password": server.password,
                }],
            },
            "streamSettings": stream,
            "tag": "out",
        }
    elif proto in ("ss", "shadowsocks"):
        if not server.password or not server.cipher:
            return None
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server.host,
                    "port": port_int,
                    "method": server.cipher,
                    "password": server.password,
                }],
            },
            "tag": "out",
        }
    else:
        # hysteria2 and unknown protocols — xray-core doesn't speak
        # hysteria2 (separate fork), so we don't run Stage 2 on those
        # and trust the Stage 1 result.
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [inbound],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["socks-in"],
                "outboundTag": "out",
            }],
        },
    }


async def _xray_curl_test(socks_port: int) -> Optional[int]:
    """Try every connectivity-check target through the SOCKS proxy until
    one succeeds.  Returns latency in ms on success, None on full failure.
    """
    for target in XRAY_TEST_TARGETS:
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                "--max-time", str(int(XRAY_TEST_TIMEOUT_S)),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=XRAY_TEST_TIMEOUT_S + 1.0
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            code = stdout.decode("ascii", errors="ignore").strip()
            if code in ("200", "204"):
                return max(1, elapsed_ms)
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            continue
        except Exception:
            continue
    return None


async def xray_probe(server: PublicServer) -> Optional[int]:
    """Stage-2 probe: spin up xray with this server as outbound, fetch a
    connectivity-check URL through the resulting SOCKS proxy, return
    the elapsed time in ms.  Returns None on any failure — wrong UUID,
    wrong password, dead backend, missing transport metadata, or
    transport unsupported by xray (hysteria2).
    """
    if XRAY_BINARY is None:
        return None
    # Reality requires fields we don't always have parsed.  Skip rather
    # than emit a config that will fail handshake every time.
    if (server.security or "").lower() == "reality":
        return None

    socks_port = _find_free_port()
    config = _xray_config(server, socks_port)
    if config is None:
        return None

    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray-probe-")
    proc: Optional[asyncio.subprocess.Process] = None
    try:
        os.write(fd, json.dumps(config).encode("utf-8"))
        os.close(fd)
        try:
            proc = await asyncio.create_subprocess_exec(
                XRAY_BINARY, "run", "-c", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (FileNotFoundError, OSError):
            return None

        # Give xray a moment to bind the SOCKS port.
        await asyncio.sleep(XRAY_STARTUP_DELAY_S)
        if proc.returncode is not None:
            # xray exited early — bad config.
            return None

        try:
            return await asyncio.wait_for(
                _xray_curl_test(socks_port),
                timeout=XRAY_OVERALL_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            return None
    except Exception as e:
        logging.debug("xray_probe %s: %s", server.host, e)
        return None
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
        try:
            os.unlink(config_path)
        except OSError:
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

    # ---- Stage 2: real V2Ray engine verification via xray-core ----
    #
    # Stage 1 (above) is the fast pre-filter that drops the obvious
    # garbage from the 5000+ raw subscription entries.  Stage 2 runs
    # actual xray-core processes against every Stage 1 survivor and
    # only keeps the ones a real client can establish a tunnel through —
    # exactly what V2RAY NG does on its own test path.  This is what
    # finally closes the long tail of "TCP+TLS+WS-Upgrade pass, but
    # the inner V2Ray protocol fails the moment we send real bytes"
    # false positives.
    #
    # If xray isn't on PATH (workflow hasn't been updated to install
    # it), we skip Stage 2 with a warning and emit Stage 1 results
    # unchanged — degraded accuracy but the workflow still produces a
    # JSON.
    if XRAY_BINARY is None:
        logging.warning(
            "xray binary not found on PATH — skipping Stage 2 (real engine verification). "
            "Install xray-core in the workflow for V2RAY NG-grade accuracy; "
            "see tools/v2ray-prober/probe-workflow.yml.example."
        )
    elif verified:
        logging.info(
            "Stage 2: verifying %d Stage 1 survivors with %s (concurrency=%d)",
            len(verified), XRAY_BINARY, XRAY_CONCURRENCY,
        )
        stage1 = list(verified)
        verified = []
        xray_sem = asyncio.Semaphore(XRAY_CONCURRENCY)
        progress = {"done": 0}

        async def xray_verify(server: PublicServer) -> None:
            if len(verified) >= limit:
                return
            async with xray_sem:
                if len(verified) >= limit:
                    return
                ping = await xray_probe(server)
                progress["done"] += 1
                if progress["done"] % 50 == 0:
                    logging.info(
                        "Stage 2 progress: %d/%d (%d verified so far)",
                        progress["done"], len(stage1), len(verified),
                    )
                if ping is not None:
                    # Replace Stage 1 ping with Stage 2 ping (which is
                    # actual end-to-end latency through the tunnel,
                    # not just the TCP+TLS handshake time).
                    server.ping = f"{ping}ms"
                    server.status = "online"
                    verified.append(server)

        await asyncio.gather(*(xray_verify(s) for s in stage1))
        logging.info(
            "Stage 2: %d / %d Stage 1 survivors passed the real engine test",
            len(verified), len(stage1),
        )

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
