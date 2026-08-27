#!/usr/bin/env bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup (Ultra-Performance)
#  Full Port Range (1-65535) + Fix UDP Freeze & Browsing Issues
# ============================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

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
    echo "║   MinaProNet VPN - Hysteria Max Performance      ║"
    echo "║       Port Range 1-65535 | UDP Fix Applied       ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}
msg()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
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
    apt-get install -y -qq curl wget openssl ca-certificates iptables \
        iptables-persistent conntrack iproute2 >/dev/null 2>&1
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
    if ! wget -q --show-progress -O "$TMP" \
        "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${ARCH}"; then
        err "Download failed"; rm -f "$TMP"; exit 1
    fi

    chmod 755 "$TMP"; mv -f "$TMP" "$HYSTERIA_BIN"
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
    local CN="hysteria.mnet"
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" -out "$HYSTERIA_CERT" \
        -subj "/CN=${CN}" -days 3650 2>/dev/null
    chmod 640 "$HYSTERIA_KEY"; chmod 644 "$HYSTERIA_CERT"
    chown root:"$HYSTERIA_USER" "$HYSTERIA_KEY" "$HYSTERIA_CERT"
    msg "Certificate generated"
}

get_config() {
    echo ""; echo -e "${BOLD}=== Server Configuration ===${NC}"; echo ""
    
    read -rp "$(echo -e "${CYAN}Enter Listen Main Port [default: 443]: ${NC}")" LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-443}

    read -rp "$(echo -e "${CYAN}Enable Full Port Hopping 1-65535? [Y/n]: ${NC}")" HOP_CHOICE
    if [[ "${HOP_CHOICE,,}" != "n" ]]; then
        USE_PORT_HOPPING=true
        PORT_RANGE_START=1
        PORT_RANGE_END=65535
        info "Port Hopping Enabled: 1-65535 -> Redirecting to ${LISTEN_PORT}"
    else
        USE_PORT_HOPPING=false
        info "Single Port Mode: ${LISTEN_PORT}"
    fi

    read -rp "$(echo -e "${CYAN}Obfs password [default: random]: ${NC}")" OBFS
    OBFS=${OBFS:-$(openssl rand -hex 12)}
    read -rp "$(echo -e "${CYAN}Auth password [default: random]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-$(openssl rand -hex 16)}

    read -rp "$(echo -e "${CYAN}Max Upload Mbps per client [default: 200]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-200}
    read -rp "$(echo -e "${CYAN}Max Download Mbps per client [default: 500]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-500}
}

create_config() {
    info "Creating optimized Hysteria configuration..."
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
    "recv_window_conn": 16777216,
    "recv_window_client": 67108864,
    "max_conn_client": 1024,
    "disable_mtu_discovery": false
}
EOF
    chmod 640 "$HYSTERIA_CONFIG"; chown root:"$HYSTERIA_USER" "$HYSTERIA_CONFIG"
    msg "Configuration created"
}

apply_sysctl() {
    info "Applying high-performance UDP & System settings..."
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true

    cat > "$SYSCTL_FILE" << 'EOF'
# --- Hysteria High-Performance Sysctl ---
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# تمكين التوجيه لضمان سلاسة الاتصال واستقرار التصفح
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# تحسين أداء UDP Conntrack لمنع انقطاع الصوت والبث
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 300

# إعدادات الحماية والأداء للشبكة
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
        msg "BBR Congestion Control Enabled"
    fi
    msg "Kernel settings applied"
}

write_firewall_script() {
    info "Writing clean & fast firewall rules..."
    
    cat > "$FW_SCRIPT" << EOFW
#!/usr/bin/env bash
IFACE="${IFACE}"
HY_UID="${HY_UID}"
LISTEN_PORT="${LISTEN_PORT}"

# تنظيف السلاسل الخاصة بـ Hysteria
iptables -t nat -D PREROUTING -i "\$IFACE" -p udp --dport 1:65535 -j REDIRECT --to-ports \$LISTEN_PORT 2>/dev/null || true
iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# 1. إعداد Port Hopping المدى الكامل (1-65535)
if [ "${USE_PORT_HOPPING}" = true ]; then
    iptables -t nat -A PREROUTING -i "\$IFACE" -p udp --dport 1:65535 -j REDIRECT --to-ports \$LISTEN_PORT
fi

# 2. حل مشكلة التصفح والتعليق عبر ضبط TCP MSS Clamping
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# 3. منع السبام والهجمات الأساسية دون تقييد بيانات المستخدم
iptables -N HY-OUT 2>/dev/null || iptables -F HY-OUT
iptables -A HY-OUT -o lo -j RETURN
iptables -A HY-OUT -p tcp -m multiport --dports 25,465,587 -j REJECT
iptables -A HY-OUT -j RETURN

iptables -D OUTPUT -m owner --uid-owner "\$HY_UID" -j HY-OUT 2>/dev/null || true
iptables -A OUTPUT -m owner --uid-owner "\$HY_UID" -j HY-OUT

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
fi
exit 0
EOFW
    chmod 750 "$FW_SCRIPT"
    bash "$FW_SCRIPT" && msg "Firewall rules applied"
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

[Service]
Type=simple
User=${HYSTERIA_USER}
Group=${HYSTERIA_USER}
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

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
        err "Failed to start. Service logs:"
        journalctl -u hysteria-server --no-pager -n 20
        exit 1
    fi
}

show_info() {
    local APP_PORT
    [ "$USE_PORT_HOPPING" = true ] && APP_PORT="1-65535" || APP_PORT="${LISTEN_PORT}"
    echo -e "\n${GREEN}${BOLD}=== App Settings (MinaProNet VPN) ===${NC}"
    echo -e "  UDP Server : ${BOLD}${SERVER_IP}${NC}"
    echo -e "  UDP Port   : ${BOLD}${APP_PORT}${NC}"
    echo -e "  Obfs       : ${BOLD}${OBFS}${NC}"
    echo -e "  Auth       : ${BOLD}${AUTH_STR}${NC}"
    echo -e "  UpDown     : ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
}

# ======================== MAIN ========================
check_root
detect_iface
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
start_services
show_info
echo -e "${GREEN}${BOLD}Done — UDP Freeze Fixed & Full Port Range Active!${NC}"
