#!/usr/bin/env bash
#============================================================
# MinaProNet VPN - Hysteria UDP Server Setup (Full Port Hopping 1-65535)
# Compatible with MinaProNetVPN Tunnel App (Hysteria v1)
# Ubuntu 20.04 / 22.04 / 24.04
#============================================================

set -uo pipefail

RED='[0;31m'; GREEN='[0;32m'; YELLOW='[1;33m'
CYAN='[0;36m'; BOLD='[1m'; NC='[0m'

HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_VER="v1.3.5"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
HYSTERIA_CERT="${HYSTERIA_DIR}/server.crt"
HYSTERIA_KEY="${HYSTERIA_DIR}/server.key"
HYSTERIA_USER="hysteria"
SVC_MAIN="/etc/systemd/system/hysteria-server.service"
SVC_FW="/etc/systemd/system/hysteria-firewall.service"
FW_SCRIPT="${HYSTERIA_DIR}/firewall.sh"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-udp.conf"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║ MinaProNet VPN - Hysteria UDP (Full Hopping)   ║"
    echo "║ Port Hopping Range: 1-65535 Enabled             ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

msg() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

check_root() {
    [ "$(id -u)" -eq 0 ] || { err "Must run as root (sudo)"; exit 1; }
}

detect_iface() {
    IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [ -n "${IFACE:-}" ] || IFACE=$(ls /sys/class/net | grep -v '^lo$' | head -n1)
    info "Main interface: ${IFACE}"
}

get_server_ip() {
    SERVER_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "${SERVER_IP:-}" ]; then
        SERVER_IP=$(curl -s4m5 https://ifconfig.me 2>/dev/null || true)
    fi
    [ -n "${SERVER_IP:-}" ] || read -rp "Enter your server IP: " SERVER_IP
    msg "Server IP: ${SERVER_IP}"
}

install_deps() {
    info "Installing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl wget openssl ca-certificates iptables         iptables-persistent conntrack iproute2 >/dev/null 2>&1
    msg "Dependencies installed"
}

install_hysteria() {
    local ARCH TMP
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    info "Downloading Hysteria ${HYSTERIA_VER} (${ARCH})..."
    TMP=$(mktemp)
    if ! wget -q --show-progress -O "$TMP" "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${ARCH}"; then
        err "Download failed"
        rm -f "$TMP"
        exit 1
    fi

    if ! head -c4 "$TMP" | grep -q $'ELF'; then
        err "Downloaded file is not a valid binary"
        rm -f "$TMP"
        exit 1
    fi

    chmod 755 "$TMP"
    mv -f "$TMP" "$HYSTERIA_BIN"
    "$HYSTERIA_BIN" version >/dev/null 2>&1 || warn "Binary did not report a version"
    msg "Hysteria installed at ${HYSTERIA_BIN}"
}

create_user() {
    if ! id "$HYSTERIA_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$HYSTERIA_USER"
    fi
    HY_UID=$(id -u "$HYSTERIA_USER")
    msg "Service user: ${HYSTERIA_USER} (uid ${HY_UID})"
}

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"; chmod 750 "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        warn "Certificate exists, skipping"; return
    fi
    info "Generating self-signed certificate..."
    local CN="bing.com"
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" -out "$HYSTERIA_CERT"         -subj "/CN=${CN}" -days 3650 2>/dev/null
    chmod 640 "$HYSTERIA_KEY"; chmod 644 "$HYSTERIA_CERT"
    chown root:"$HYSTERIA_USER" "$HYSTERIA_KEY" "$HYSTERIA_CERT"
    msg "Certificate generated (CN=${CN})"
}

get_config() {
    echo ""; echo -e "${BOLD}=== Server Configuration ===${NC}"; echo ""

    read -rp "$(echo -e "${CYAN}Main Listening Port [default: 5666]: ${NC}")" LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-5666}

    read -rp "$(echo -e "${CYAN}Obfs password [default: random]: ${NC}")" OBFS
    OBFS=${OBFS:-$(openssl rand -hex 12)}

    read -rp "$(echo -e "${CYAN}Auth password [default: random]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-$(openssl rand -hex 16)}

    read -rp "$(echo -e "${CYAN}Max Upload Mbps per client [default: 100]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-100}

    read -rp "$(echo -e "${CYAN}Max Download Mbps per client [default: 100]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-100}

    echo ""
}

create_config() {
    info "Creating configuration..."
    cat > "$HYSTERIA_CONFIG" << EOF
{
  "listen": ":${LISTEN_PORT}",
  "cert": "${HYSTERIA_CERT}",
  "key": "${HYSTERIA_KEY}",
  "obfs": "${OBFS}",
  "auth": {
    "mode": "password",
    "config": { "password": "${AUTH_STR}" }
  },
  "up_mbps": ${UP_MBPS},
  "down_mbps": ${DOWN_MBPS},
  "disable_udp": false,
  "recv_window_conn": 5767168,
  "recv_window_client": 23068672,
  "max_conn_client": 128
}
EOF
    chmod 640 "$HYSTERIA_CONFIG"; chown root:"$HYSTERIA_USER" "$HYSTERIA_CONFIG"
    msg "Configuration created"
}

apply_sysctl() {
    info "Applying kernel settings..."
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true

    cat > "$SYSCTL_FILE" << 'EOF'
# Kernel performance tuning & forwarding for VPN tunneling
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

net.ipv4.tcp_syncookies = 1
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
        msg "BBR enabled"
    fi
    msg "Kernel settings applied (ip_forward=1 active)"
}

write_firewall_script() {
    info "Writing firewall rules for full UDP Port Hopping (1-65535)..."

    cat > "$FW_SCRIPT" << EOFW
#!/usr/bin/env bash

IFACE="${IFACE}"
LISTEN_PORT="${LISTEN_PORT}"

# Flush existing iptables NAT / INPUT rules cleanly first
iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -t nat -F POSTROUTING 2>/dev/null || true

# Enable NAT / Masquerade
iptables -t nat -A POSTROUTING -o "\$IFACE" -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o "\$IFACE" -j MASQUERADE 2>/dev/null || true

# Redirect UDP ports EXCEPT listening port itself to avoid circular loop
iptables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport 1:\$((LISTEN_PORT-1)) -j REDIRECT --to-ports "\$LISTEN_PORT" 2>/dev/null || true
iptables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport \$((LISTEN_PORT+1)):65535 -j REDIRECT --to-ports "\$LISTEN_PORT" 2>/dev/null || true

ip6tables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport 1:\$((LISTEN_PORT-1)) -j REDIRECT --to-ports "\$LISTEN_PORT" 2>/dev/null || true
ip6tables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport \$((LISTEN_PORT+1)):65535 -j REDIRECT --to-ports "\$LISTEN_PORT" 2>/dev/null || true

# Explicitly ACCEPT UDP traffic on all ports in INPUT chain
iptables -I INPUT -i "\$IFACE" -p udp -j ACCEPT
ip6tables -I INPUT -i "\$IFACE" -p udp -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
fi
exit 0
EOFW
    chmod 750 "$FW_SCRIPT"
    bash "$FW_SCRIPT" && msg "Firewall rules applied (1-65535 UDP Redirect Fixed)" || err "Firewall script failed"
}

create_services() {
    info "Creating systemd services..."
    cat > "$SVC_FW" << EOF
[Unit]
Description=Hysteria firewall rules
After=network-online.target
Wants=network-online.target
Before=hysteria-server.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${FW_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SVC_MAIN" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN)
After=network-online.target hysteria-firewall.service
Wants=network-online.target
Requires=hysteria-firewall.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    msg "Services created"
}

start_services() {
    info "Starting services..."
    systemctl enable hysteria-firewall >/dev/null 2>&1
    systemctl restart hysteria-firewall
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        msg "Hysteria server is RUNNING"
    else
        err "Failed to start. Logs:"
        journalctl -u hysteria-server --no-pager -n 25
        exit 1
    fi
}

verify_server() {
    echo ""; info "Verification"
    ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT}"         && msg "1/3 Listening on UDP ${LISTEN_PORT}" || err "1/3 NOT listening"

    [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]         && msg "2/3 ip_forward enabled" || err "2/3 ip_forward disabled"

    iptables -t nat -S PREROUTING 2>/dev/null | grep -q "REDIRECT"         && msg "3/3 Port hopping active" || err "3/3 Port hopping NOT active"
    echo ""
}

show_info() {
    echo -e "${GREEN}${BOLD}=== App Settings (MinaProNet VPN) ===${NC}"
    echo -e " UDP Server : ${BOLD}${SERVER_IP}${NC}"
    echo -e " UDP Port   : ${BOLD}1-65535${NC} (Listen Port: ${LISTEN_PORT})"
    echo -e " Obfs       : ${BOLD}${OBFS}${NC}"
    echo -e " Auth       : ${BOLD}${AUTH_STR}${NC}"
    echo -e " UpDown     : ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
    echo -e "${BOLD}=== Management ===${NC}"
    echo -e " systemctl status hysteria-server"
    echo -e " bash $0 --uninstall"
    echo ""
    umask 077
    cat > "${HYSTERIA_DIR}/connection-info.txt" << EOF
UDP Server: ${SERVER_IP}
UDP Port: 1-65535
Obfs: ${OBFS}
Auth: ${AUTH_STR}
UpDown: ${UP_MBPS}:${DOWN_MBPS}
Internal: ${LISTEN_PORT}
EOF
    chmod 600 "${HYSTERIA_DIR}/connection-info.txt"
}

uninstall() {
    warn "Uninstalling..."
    systemctl disable --now hysteria-server hysteria-firewall 2>/dev/null
    iptables -t nat -F PREROUTING 2>/dev/null
    iptables -t nat -F POSTROUTING 2>/dev/null
    ip6tables -t nat -F PREROUTING 2>/dev/null
    ip6tables -t nat -F POSTROUTING 2>/dev/null
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1

    rm -f "$SVC_MAIN" "$SVC_FW" "$HYSTERIA_BIN" "$SYSCTL_FILE"
    rm -rf "$HYSTERIA_DIR"
    userdel "$HYSTERIA_USER" 2>/dev/null
    systemctl daemon-reload; sysctl --system >/dev/null 2>&1
    msg "Uninstalled"
    exit 0
}

# MAIN
check_root
detect_iface
[ "${1:-}" = "--uninstall" ] && uninstall

print_banner
get_server_ip
install_deps
install_hysteria
create_user
generate_cert
get_config
create_config
apply_sysctl
write_firewall_script
create_services
systemctl daemon-reload
start_services
verify_server
show_info
echo -e "${GREEN}${BOLD}Done — server is set up with full port hopping (1-65535).${NC}"
