#!/bin/bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server (SSH-cert auth)
#  Hysteria v1 + external auth via SSH certificate
#  For Ubuntu 18.04 / 20.04 / 22.04 / 24.04
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
HYSTERIA_CERT="${HYSTERIA_DIR}/server.crt"
HYSTERIA_KEY="${HYSTERIA_DIR}/server.key"
HYSTERIA_SERVICE="/etc/systemd/system/hysteria-server.service"
IPTABLES_SCRIPT="${HYSTERIA_DIR}/iptables.sh"

# --- Cert-auth bits ---
CA_DIR="${HYSTERIA_DIR}/ca"
TRUSTED_CA_PUB="${HYSTERIA_DIR}/trusted_ca.pub"
CA_PRIV="${CA_DIR}/ca"          # only if CA is generated locally
AUTH_DIR="${HYSTERIA_DIR}/auth"
AUTH_VENV="${AUTH_DIR}/venv"
AUTH_SCRIPT="${AUTH_DIR}/server.py"
AUTH_ENV="${AUTH_DIR}/auth.env"
AUTH_SERVICE="/etc/systemd/system/hysteria-cert-auth.service"
AUTH_LOG="/var/log/hysteria-auth.log"
AUTH_PORT="8082"

LISTEN_PORT="36712"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   MinaProNet VPN - Hysteria UDP (cert auth)     ║"
    echo "║       SSH-style certificate authentication       ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_msg()  { echo -e "${GREEN}[✓]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
print_err()  { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${CYAN}[i]${NC} $1"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_err "Must run as root (sudo)"
        exit 1
    fi
}

apt_update_safe() {
    apt-get update -qq \
        -o APT::Update::Post-Invoke-Success="" \
        -o APT::Update::Post-Invoke="" > /dev/null 2>&1 || true
}

get_server_ip() {
    print_info "Detecting server IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me 2>/dev/null \
              || curl -s4m5 ip.sb 2>/dev/null \
              || curl -s4m5 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        read -rp "Enter your server IP: " SERVER_IP
    fi
    print_msg "Server IP: ${SERVER_IP}"
}

install_deps() {
    print_info "Installing dependencies..."
    apt_update_safe
    apt-get install -y -qq \
        curl wget openssl iptables nftables conntrack \
        openssh-client python3 python3-venv python3-pip \
        > /dev/null 2>&1
    print_msg "Dependencies installed"
}

install_hysteria() {
    print_info "Downloading Hysteria v1..."
    local ARCH
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) print_err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    local DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-${ARCH}"

    if ! wget -q --show-progress -O "$HYSTERIA_BIN" "$DOWNLOAD_URL"; then
        print_err "Failed to download"
        exit 1
    fi
    chmod +x "$HYSTERIA_BIN"
    print_msg "Hysteria v1 installed"
}

generate_tls_cert() {
    mkdir -p "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        print_warn "TLS certificate exists, skipping"
        return
    fi
    print_info "Generating self-signed TLS certificate..."
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" \
        -out "$HYSTERIA_CERT" \
        -subj "/CN=bing.com" \
        -days 3650 2>/dev/null
    chmod 600 "$HYSTERIA_KEY"
    chmod 644 "$HYSTERIA_CERT"
    print_msg "TLS certificate generated"
}

fix_dns() {
    print_info "Checking DNS..."
    if ! nslookup google.com > /dev/null 2>&1; then
        print_warn "Fixing DNS..."
        cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
        cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    fi
    if nslookup google.com > /dev/null 2>&1; then
        print_msg "DNS working"
    else
        print_warn "DNS may have issues"
    fi
}

# ============================================================
# SSH-CA setup (the trusted authority for cert-based auth)
# ============================================================
setup_ssh_ca() {
    mkdir -p "$CA_DIR"
    chmod 700 "$CA_DIR"

    if [ -f "$TRUSTED_CA_PUB" ]; then
        print_warn "Trusted CA already configured: $TRUSTED_CA_PUB"
        return
    fi

    echo ""
    echo -e "${BOLD}=== SSH Certificate Authority ===${NC}"
    echo -e "${CYAN}Choose how to set up the trusted CA:${NC}"
    echo "  1) Paste an EXISTING CA public key (reuse your SSH CA)"
    echo "  2) Generate a NEW CA on this server"
    read -rp "$(echo -e "${CYAN}Choice [1/2, default 1]: ${NC}")" CA_MODE
    CA_MODE=${CA_MODE:-1}

    if [ "$CA_MODE" = "1" ]; then
        echo ""
        echo -e "${CYAN}Paste your CA public key on ONE line${NC}"
        echo -e "${CYAN}(e.g. 'ecdsa-sha2-nistp521 AAAAE2VjZ... ca@host'), then press Enter:${NC}"
        read -r CA_PUB_LINE
        if [ -z "$CA_PUB_LINE" ]; then
            print_err "Empty input"; exit 1
        fi
        echo "$CA_PUB_LINE" > "$TRUSTED_CA_PUB"
        # Sanity-check the key parses
        if ! ssh-keygen -lf "$TRUSTED_CA_PUB" > /dev/null 2>&1; then
            print_err "Provided CA key is not a valid SSH public key"
            rm -f "$TRUSTED_CA_PUB"
            exit 1
        fi
        chmod 644 "$TRUSTED_CA_PUB"
        print_msg "Trusted CA saved (imported)"
    else
        print_info "Generating new ed25519 CA..."
        ssh-keygen -t ed25519 -f "$CA_PRIV" -N "" -C "minapronet-ca-$(date +%Y%m%d)" \
            > /dev/null 2>&1
        cp "${CA_PRIV}.pub" "$TRUSTED_CA_PUB"
        chmod 600 "$CA_PRIV"
        chmod 644 "$TRUSTED_CA_PUB"
        print_msg "New CA generated"
        echo ""
        echo -e "${YELLOW}=== NEW CA created. Keep the private key safe! ===${NC}"
        echo -e "  Private key: ${BOLD}${CA_PRIV}${NC}"
        echo -e "  Public key : ${BOLD}${TRUSTED_CA_PUB}${NC}"
        echo ""
    fi

    echo ""
    echo -e "${CYAN}CA fingerprint:${NC}"
    ssh-keygen -lf "$TRUSTED_CA_PUB"
    echo ""
}

get_config() {
    echo ""
    echo -e "${BOLD}=== Server Configuration ===${NC}"
    echo ""

    echo -e "${CYAN}Port range. Examples: 443 / 1-65535 / 20000-50000${NC}"
    read -rp "$(echo -e "${CYAN}Enter port/range [default: 1-65535]: ${NC}")" PORT_INPUT
    PORT_INPUT=${PORT_INPUT:-1-65535}

    if [[ "$PORT_INPUT" == *"-"* ]]; then
        PORT_RANGE_START=$(echo "$PORT_INPUT" | cut -d'-' -f1)
        PORT_RANGE_END=$(echo "$PORT_INPUT" | cut -d'-' -f2)
        USE_PORT_HOPPING=true
        print_info "Port hopping: ${PORT_RANGE_START}-${PORT_RANGE_END} -> ${LISTEN_PORT}"
    else
        LISTEN_PORT="$PORT_INPUT"
        USE_PORT_HOPPING=false
        print_info "Single port: ${LISTEN_PORT}"
    fi

    read -rp "$(echo -e "${CYAN}Obfs password [default: minapronet]: ${NC}")" OBFS
    OBFS=${OBFS:-minapronet}

    read -rp "$(echo -e "${CYAN}Allowed cert principal [default: minapronet]: ${NC}")" PRINCIPAL
    PRINCIPAL=${PRINCIPAL:-minapronet}

    read -rp "$(echo -e "${CYAN}Upload Mbps [default: 100]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-100}

    read -rp "$(echo -e "${CYAN}Download Mbps [default: 100]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-100}

    echo ""
}

# ============================================================
# Auth server (Python) — verifies SSH cert against trusted CA
# ============================================================
install_auth_server() {
    print_info "Installing cert-auth server..."
    mkdir -p "$AUTH_DIR"

    # venv with up-to-date cryptography (>=40 for load_ssh_public_identity)
    if [ ! -d "$AUTH_VENV" ]; then
        python3 -m venv "$AUTH_VENV"
    fi
    "$AUTH_VENV/bin/pip" install --quiet --upgrade pip > /dev/null 2>&1 || true
    "$AUTH_VENV/bin/pip" install --quiet --upgrade 'cryptography>=41' > /dev/null 2>&1

    # Verify import works
    if ! "$AUTH_VENV/bin/python" -c "from cryptography.hazmat.primitives.serialization import load_ssh_public_identity, SSHCertificate" 2>/dev/null; then
        print_err "cryptography lib missing SSHCertificate support"
        exit 1
    fi

    cat > "$AUTH_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""Hysteria external-auth backend: verifies SSH certificates."""
import base64
import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        SSHCertificate,
        SSHCertificateType,
        load_ssh_public_identity,
        load_ssh_public_key,
    )
except Exception as e:
    sys.stderr.write("cryptography import failed: %s\n" % e)
    sys.exit(1)

TRUSTED_CA_PATH   = os.environ.get("HYS_CA",        "/etc/hysteria/trusted_ca.pub")
ALLOWED_PRINCIPAL = os.environ.get("HYS_PRINCIPAL", "minapronet")
LISTEN_HOST       = os.environ.get("HYS_AUTH_HOST", "127.0.0.1")
LISTEN_PORT       = int(os.environ.get("HYS_AUTH_PORT", "8082"))
LOG_FILE          = os.environ.get("HYS_AUTH_LOG",  "/var/log/hysteria-auth.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

with open(TRUSTED_CA_PATH, "rb") as f:
    _ca_data = f.read().strip()
TRUSTED_CA_KEY = load_ssh_public_key(_ca_data)
TRUSTED_CA_BLOB = TRUSTED_CA_KEY.public_bytes(
    Encoding.OpenSSH, PublicFormat.OpenSSH
).split()[1]
logging.info("Loaded trusted CA from %s (principal=%s)",
             TRUSTED_CA_PATH, ALLOWED_PRINCIPAL)


def verify_cert(auth_field):
    """Return (ok, msg). `auth_field` is whatever the client sent (after
    Hysteria's base64-decode it's still a base64 string in the request)."""
    try:
        if not auth_field:
            return False, "empty auth"

        # Hysteria sends `auth` already base64-encoded in the JSON;
        # try to decode, fall back to raw text if not valid base64.
        raw = None
        try:
            raw = base64.b64decode(auth_field, validate=True)
        except Exception:
            raw = (auth_field.encode() if isinstance(auth_field, str)
                   else auth_field)

        cert_text = raw.strip()
        if b"-cert-v01@openssh.com" not in cert_text:
            return False, "not an openssh certificate"

        identity = load_ssh_public_identity(cert_text)
        if not isinstance(identity, SSHCertificate):
            return False, "not a certificate"

        # 1) Cryptographic signature
        try:
            identity.verify_cert_signature()
        except InvalidSignature:
            return False, "invalid signature"

        # 2) Signing CA must equal trusted CA
        signing_blob = identity.signature_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        ).split()[1]
        if signing_blob != TRUSTED_CA_BLOB:
            return False, "untrusted CA"

        # 3) Validity window
        now = int(time.time())
        if now < identity.valid_after:
            return False, "cert not yet valid"
        if now >= identity.valid_before:
            return False, "cert expired"

        # 4) Must be a USER cert
        if identity.type != SSHCertificateType.USER:
            return False, "not a user cert"

        # 5) Principal check
        principals = [p.decode() if isinstance(p, bytes) else p
                      for p in identity.valid_principals]
        if ALLOWED_PRINCIPAL and ALLOWED_PRINCIPAL not in principals:
            return False, "principal '%s' not in %r" % (ALLOWED_PRINCIPAL, principals)

        key_id = identity.key_id
        if isinstance(key_id, bytes):
            key_id = key_id.decode("utf-8", "replace")
        return True, "ok key_id=%s" % key_id

    except Exception as e:
        return False, "parse error: %s" % e.__class__.__name__


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.client_address[0], fmt % args)

    def do_GET(self):
        self._reply(200, {"ok": True, "msg": "alive"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 65536:
            self._reply(400, {"ok": False, "msg": "bad length"}); return
        try:
            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self._reply(400, {"ok": False, "msg": "bad json"}); return

        client_addr = data.get("addr", "?")
        ok, msg = verify_cert(data.get("auth", ""))
        if ok:
            logging.info("AUTH OK   from %s: %s", client_addr, msg)
        else:
            logging.warning("AUTH FAIL from %s: %s", client_addr, msg)
        self._reply(200, {"ok": ok, "msg": msg})

    def _reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), AuthHandler)
    logging.info("Listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
PYEOF
    chmod 750 "$AUTH_SCRIPT"

    cat > "$AUTH_ENV" << EOF
HYS_CA=${TRUSTED_CA_PUB}
HYS_PRINCIPAL=${PRINCIPAL}
HYS_AUTH_HOST=127.0.0.1
HYS_AUTH_PORT=${AUTH_PORT}
HYS_AUTH_LOG=${AUTH_LOG}
EOF
    chmod 600 "$AUTH_ENV"

    cat > "$AUTH_SERVICE" << EOF
[Unit]
Description=Hysteria SSH-cert auth backend
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=${AUTH_ENV}
ExecStart=${AUTH_VENV}/bin/python ${AUTH_SCRIPT}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    : > "$AUTH_LOG"
    chmod 640 "$AUTH_LOG"

    systemctl daemon-reload
    systemctl enable hysteria-cert-auth > /dev/null 2>&1
    systemctl restart hysteria-cert-auth
    sleep 1

    if systemctl is-active --quiet hysteria-cert-auth; then
        print_msg "Cert-auth server running on 127.0.0.1:${AUTH_PORT}"
    else
        print_err "Cert-auth server failed:"
        journalctl -u hysteria-cert-auth --no-pager -n 20
        exit 1
    fi
}

create_config() {
    mkdir -p "$HYSTERIA_DIR"
    print_info "Creating Hysteria configuration (external auth)..."

    cat > "$HYSTERIA_CONFIG" << EOF
{
    "listen": ":${LISTEN_PORT}",
    "cert": "${HYSTERIA_CERT}",
    "key": "${HYSTERIA_KEY}",
    "obfs": "${OBFS}",
    "auth": {
        "mode": "external",
        "config": {
            "http": "http://127.0.0.1:${AUTH_PORT}/auth"
        }
    },
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS}
}
EOF
    chmod 600 "$HYSTERIA_CONFIG"
    print_msg "Configuration created"
}

optimize_kernel() {
    print_info "Optimizing kernel..."

    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true
    modprobe xt_REDIRECT 2>/dev/null || true

    cat > /etc/sysctl.d/99-hysteria-udp.conf << 'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 12
net.netfilter.nf_conntrack_udp_timeout_stream = 35
net.ipv4.tcp_fastopen = 3
EOF

    echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    sysctl -p /etc/sysctl.d/99-hysteria-udp.conf > /dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1 || true
        print_msg "BBR enabled"
    fi

    print_msg "Kernel optimized"
}

create_service() {
    print_info "Creating Hysteria systemd service..."

    cat > "$HYSTERIA_SERVICE" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN, cert auth)
After=network.target network-online.target hysteria-cert-auth.service
Wants=network-online.target
Requires=hysteria-cert-auth.service

[Service]
Type=simple
User=root
ExecStartPre=/sbin/modprobe nf_conntrack
ExecStartPre=/sbin/modprobe nf_nat
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_msg "Service created"
}

# ============================================================
# Port hopping (unchanged, just included for completeness)
# ============================================================
setup_port_hopping() {
    if [ "$USE_PORT_HOPPING" != true ]; then
        iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
        HOPPING_METHOD="direct"
        return
    fi

    print_info "Setting up port hopping..."
    if setup_nftables_redirect; then
        HOPPING_METHOD="nftables"
        print_msg "Port hopping via nftables"
    elif setup_iptables_redirect; then
        HOPPING_METHOD="iptables"
        print_msg "Port hopping via iptables"
    else
        print_warn "Port hopping setup failed - using single port"
        USE_PORT_HOPPING=false
    fi
}

setup_nftables_redirect() {
    command -v nft &>/dev/null || return 1
    nft delete table inet hysteria 2>/dev/null || true
    nft add table inet hysteria 2>/dev/null || return 1
    nft add chain inet hysteria input '{ type filter hook input priority 0; }' 2>/dev/null || return 1
    nft add rule inet hysteria input udp dport "$LISTEN_PORT" accept 2>/dev/null || return 1
    nft add rule inet hysteria input udp dport "${PORT_RANGE_START}-${PORT_RANGE_END}" accept 2>/dev/null || return 1
    nft add chain inet hysteria prerouting '{ type nat hook prerouting priority dstnat; }' 2>/dev/null || return 1
    nft add rule inet hysteria prerouting udp dport "${PORT_RANGE_START}-${PORT_RANGE_END}" redirect to :"$LISTEN_PORT" 2>/dev/null || return 1

    if nft list chain inet hysteria prerouting 2>/dev/null | grep -q "redirect"; then
        cat > "$IPTABLES_SCRIPT" << EOIPT
#!/bin/bash
nft delete table inet hysteria 2>/dev/null
nft add table inet hysteria
nft add chain inet hysteria input '{ type filter hook input priority 0; }'
nft add rule inet hysteria input udp dport ${LISTEN_PORT} accept
nft add rule inet hysteria input udp dport ${PORT_RANGE_START}-${PORT_RANGE_END} accept
nft add chain inet hysteria prerouting '{ type nat hook prerouting priority dstnat; }'
nft add rule inet hysteria prerouting udp dport ${PORT_RANGE_START}-${PORT_RANGE_END} redirect to :${LISTEN_PORT}
EOIPT
        chmod +x "$IPTABLES_SCRIPT"
        return 0
    fi

    nft delete table inet hysteria 2>/dev/null || true
    return 1
}

setup_iptables_redirect() {
    print_info "Configuring iptables..."
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true
    modprobe xt_REDIRECT 2>/dev/null || true
    iptables -t nat -F PREROUTING 2>/dev/null || true
    iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j ACCEPT 2>/dev/null || true
    iptables -t nat -A PREROUTING -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null || return 1

    if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir"; then
        if command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        command -v netfilter-persistent &>/dev/null && netfilter-persistent save > /dev/null 2>&1 || true
        cat > "$IPTABLES_SCRIPT" << EOIPT
#!/bin/bash
modprobe nf_conntrack 2>/dev/null
modprobe nf_nat 2>/dev/null
modprobe xt_REDIRECT 2>/dev/null
iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -p udp --dport ${LISTEN_PORT} -j ACCEPT
iptables -I INPUT -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j ACCEPT
iptables -t nat -A PREROUTING -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j REDIRECT --to-ports ${LISTEN_PORT}
EOIPT
        chmod +x "$IPTABLES_SCRIPT"
        return 0
    fi
    return 1
}

setup_ufw() {
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        if [ "$USE_PORT_HOPPING" = true ]; then
            ufw allow "${PORT_RANGE_START}:${PORT_RANGE_END}/udp" > /dev/null 2>&1 || true
        else
            ufw allow "${LISTEN_PORT}/udp" > /dev/null 2>&1 || true
        fi
    fi
}

persist_rules() {
    if [ -f "$IPTABLES_SCRIPT" ]; then
        if [ ! -f /etc/rc.local ] || ! grep -q "hysteria" /etc/rc.local 2>/dev/null; then
            echo "bash ${IPTABLES_SCRIPT}" >> /etc/rc.local 2>/dev/null || true
            chmod +x /etc/rc.local 2>/dev/null || true
        fi
    fi
}

start_service() {
    print_info "Starting Hysteria server..."
    systemctl enable hysteria-server > /dev/null 2>&1
    systemctl restart hysteria-server
    sleep 3

    if systemctl is-active --quiet hysteria-server; then
        print_msg "Hysteria server is RUNNING!"
    else
        print_err "Failed! Logs:"
        journalctl -u hysteria-server --no-pager -n 20
        exit 1
    fi
}

verify_server() {
    echo ""
    print_info "Running tests..."

    if ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT}"; then
        print_msg "Test 1/6: Hysteria listening on ${LISTEN_PORT}"
    else
        print_err "Test 1/6: NOT listening!"
    fi

    if systemctl is-active --quiet hysteria-cert-auth; then
        print_msg "Test 2/6: cert-auth service active"
    else
        print_err "Test 2/6: cert-auth service down!"
    fi

    if curl -sf -m 3 "http://127.0.0.1:${AUTH_PORT}/" > /dev/null 2>&1; then
        print_msg "Test 3/6: auth endpoint reachable"
    else
        print_warn "Test 3/6: auth endpoint not reachable"
    fi

    if nslookup google.com > /dev/null 2>&1; then
        print_msg "Test 4/6: DNS OK"
    else
        print_err "Test 4/6: DNS FAILED"
    fi

    if [ "$USE_PORT_HOPPING" = true ]; then
        if [ "$HOPPING_METHOD" = "nftables" ]; then
            if nft list chain inet hysteria prerouting 2>/dev/null | grep -q "redirect"; then
                print_msg "Test 5/6: Port hopping ACTIVE (nftables)"
            else
                print_err "Test 5/6: Port hopping NOT active!"
            fi
        else
            if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir"; then
                print_msg "Test 5/6: Port hopping ACTIVE (iptables)"
            else
                print_err "Test 5/6: Port hopping NOT active!"
            fi
        fi
    else
        print_msg "Test 5/6: Single port mode"
    fi

    local CT_MAX CT_COUNT
    CT_MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "0")
    CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0")
    if [ "$CT_MAX" -gt 0 ]; then
        print_msg "Test 6/6: Conntrack ${CT_COUNT}/${CT_MAX}"
    else
        print_msg "Test 6/6: Conntrack OK"
    fi
    echo ""
}

show_info() {
    local APP_PORT
    if [ "$USE_PORT_HOPPING" = true ]; then
        APP_PORT="${PORT_RANGE_START}-${PORT_RANGE_END}"
    else
        APP_PORT="${LISTEN_PORT}"
    fi

    local CA_FP
    CA_FP=$(ssh-keygen -lf "$TRUSTED_CA_PUB" 2>/dev/null | awk '{print $2}')

    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║              Server Ready!                       ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}=== App Settings (MinaProNet VPN) ===${NC}"
    echo ""
    echo -e "  ${CYAN}UDP Server  :${NC}  ${BOLD}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}UDP Port    :${NC}  ${BOLD}${APP_PORT}${NC}"
    echo -e "  ${CYAN}Obfs        :${NC}  ${BOLD}${OBFS}${NC}"
    echo -e "  ${CYAN}Auth mode   :${NC}  ${BOLD}SSH certificate${NC}"
    echo -e "  ${CYAN}Principal   :${NC}  ${BOLD}${PRINCIPAL}${NC}"
    echo -e "  ${CYAN}Trusted CA  :${NC}  ${BOLD}${CA_FP}${NC}"
    echo -e "  ${CYAN}UpDown      :${NC}  ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
    echo -e "${BOLD}=== How the client authenticates ===${NC}"
    echo ""
    echo -e "  The client puts the FULL openssh cert line as the auth string:"
    echo -e "    ${YELLOW}ecdsa-sha2-nistp521-cert-v01@openssh.com AAAA... user@host${NC}"
    echo -e "  The server verifies: signature → CA match → expiry → principal."
    echo ""
    echo -e "${BOLD}=== Sign a client public key (on a host that has the CA priv key) ===${NC}"
    echo ""
    echo -e "  ${YELLOW}ssh-keygen -s ca_priv -I user1-\$(date +%Y%m%d) \\
                -n ${PRINCIPAL} -V +52w client_id_ecdsa.pub${NC}"
    echo ""
    echo -e "${BOLD}=== Management ===${NC}"
    echo ""
    echo -e "  ${YELLOW}Hysteria status:${NC}  systemctl status hysteria-server"
    echo -e "  ${YELLOW}Auth status    :${NC}  systemctl status hysteria-cert-auth"
    echo -e "  ${YELLOW}Auth logs      :${NC}  tail -f ${AUTH_LOG}"
    echo -e "  ${YELLOW}Show trusted CA:${NC}  cat ${TRUSTED_CA_PUB}"
    echo -e "  ${YELLOW}Remove         :${NC}  bash $0 --uninstall"
    echo ""

    cat > "${HYSTERIA_DIR}/connection-info.txt" << EOF
=======================================
 MinaProNet VPN - Connection Details
=======================================
UDP Server:   ${SERVER_IP}
UDP Port:     ${APP_PORT}
Obfs:         ${OBFS}
Auth mode:    SSH certificate (external)
Principal:    ${PRINCIPAL}
Trusted CA:   ${CA_FP}
UpDown:       ${UP_MBPS}:${DOWN_MBPS}
Internal:     ${LISTEN_PORT}
Port-hop:     ${HOPPING_METHOD:-direct}
Auth backend: http://127.0.0.1:${AUTH_PORT}/auth
=======================================
EOF
}

uninstall() {
    print_warn "Uninstalling..."
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    systemctl stop hysteria-cert-auth 2>/dev/null || true
    systemctl disable hysteria-cert-auth 2>/dev/null || true
    rm -f "$HYSTERIA_SERVICE" "$AUTH_SERVICE"
    rm -f "$HYSTERIA_BIN"

    nft delete table inet hysteria 2>/dev/null || true
    iptables -t nat -F PREROUTING 2>/dev/null || true
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    rm -rf "$HYSTERIA_DIR"
    rm -f /etc/sysctl.d/99-hysteria-udp.conf
    rm -f "$AUTH_LOG"
    sysctl --system > /dev/null 2>&1 || true
    systemctl daemon-reload
    sed -i '/hysteria/d' /etc/rc.local 2>/dev/null || true

    print_msg "Uninstalled"
    exit 0
}

# ============================================================
# Helper sub-commands
# ============================================================
show_ca() {
    if [ ! -f "$TRUSTED_CA_PUB" ]; then
        print_err "No trusted CA configured. Run the script first."
        exit 1
    fi
    echo ""
    echo -e "${BOLD}Trusted CA public key:${NC}"
    cat "$TRUSTED_CA_PUB"
    echo ""
    echo -e "${BOLD}Fingerprint:${NC}"
    ssh-keygen -lf "$TRUSTED_CA_PUB"
    echo ""
    exit 0
}

sign_key() {
    # Usage: $0 --sign-key <client_pub.pub> [principal] [validity]
    local CLIENT_PUB="$2"
    local PRINC="${3:-minapronet}"
    local VALIDITY="${4:-+52w}"

    if [ -z "$CLIENT_PUB" ] || [ ! -f "$CLIENT_PUB" ]; then
        print_err "Usage: $0 --sign-key <client_pub.pub> [principal] [validity]"
        exit 1
    fi
    if [ ! -f "$CA_PRIV" ]; then
        print_err "CA private key not on this host ($CA_PRIV). Sign on the box that holds it."
        exit 1
    fi
    local KEYID="user-$(date +%Y%m%d%H%M%S)"
    ssh-keygen -s "$CA_PRIV" -I "$KEYID" -n "$PRINC" -V "$VALIDITY" "$CLIENT_PUB"
    print_msg "Signed: ${CLIENT_PUB%.pub}-cert.pub"
    exit 0
}

# ======================== MAIN ========================

case "$1" in
    --uninstall)  check_root; uninstall ;;
    --show-ca)    show_ca ;;
    --sign-key)   check_root; sign_key "$@" ;;
esac

print_banner
check_root
get_server_ip
install_deps
install_hysteria
generate_tls_cert
fix_dns
setup_ssh_ca
get_config
install_auth_server
create_config
optimize_kernel
create_service
setup_port_hopping
setup_ufw
persist_rules
start_service
verify_server
show_info

echo -e "${GREEN}${BOLD}Done! Server is ready.${NC}"
echo ""
