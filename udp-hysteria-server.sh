#!/usr/bin/env bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup (Full Fixed)
#  Port Range: 1-65535 -> Internal Port: 36712 (SSL Safe)
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
    echo "║   MinaProNet VPN - Hysteria Full Fixed Installer  ║"
    echo "║       Port Range 1-65535 | SSL-Tunnel Safe       ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

msg()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

check_root() {
    [ "$(id -u)" -eq 0 ] || { err "المشغل ليس root!"; exit 1; }
}

detect_iface() {
    IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [ -n "${IFACE:-}" ] || IFACE=$(ls /sys/class/net | grep -v '^lo$' | head -n1)
}

get_server_ip() {
    SERVER_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "${SERVER_IP:-}" ]; then
        SERVER_IP=$(curl -s4m5 https://ifconfig.me 2>/dev/null || true)
    fi
}

install_deps() {
    info "تثبيت الحزم الأساسية وإعداد الجدار الناري..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl wget openssl ca-certificates iptables \
        iptables-persistent conntrack iproute2 >/dev/null 2>&1
    ufw disable 2>/dev/null || true
    msg "تم تثبيت المكونات وإلغاء ufw لضمان مرور UDP"
}

install_hysteria() {
    local ARCH TMP
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) err "المعالج غير مدعوم: $ARCH"; exit 1 ;;
    esac

    info "تحميل Hysteria ${HYSTERIA_VER}..."
    TMP=$(mktemp)
    if ! wget -q --show-progress -O "$TMP" \
        "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${ARCH}"; then
        err "فشل التحميل"; rm -f "$TMP"; exit 1
    fi

    chmod 755 "$TMP"; mv -f "$TMP" "$HYSTERIA_BIN"
    msg "تم تثبيت ملف Hysteria بنجاح"
}

create_user() {
    if ! id "$HYSTERIA_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$HYSTERIA_USER"
    fi
    HY_UID=$(id -u "$HYSTERIA_USER")
}

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"; chmod 750 "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        return
    fi
    info "إنشاء شهادات التشفير..."
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" -out "$HYSTERIA_CERT" \
        -subj "/CN=hysteria.mnet" -days 3650 2>/dev/null
    chmod 640 "$HYSTERIA_KEY"; chmod 644 "$HYSTERIA_CERT"
    chown root:"$HYSTERIA_USER" "$HYSTERIA_KEY" "$HYSTERIA_CERT"
}

get_config() {
    echo -e "\n${BOLD}=== إعدادات السيرفر ===${NC}\n"
    LISTEN_PORT="36712"
    info "تم ضبط البورت الداخلي المستقل: ${LISTEN_PORT} (لتفادي التعارض مع SSL Tunnel 443)"

    read -rp "$(echo -e "${CYAN}كلمة سر Obfs [افتراضي: minapronet]: ${NC}")" OBFS
    OBFS=${OBFS:-minapronet}
    
    read -rp "$(echo -e "${CYAN}كلمة سر Auth [افتراضي: عشوائي]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-$(openssl rand -hex 16)}

    read -rp "$(echo -e "${CYAN}حد السرعة Up/Down Mbps [افتراضي: 200:500]: ${NC}")" LIMITS
    LIMITS=${LIMITS:-200:500}
    UP_MBPS=$(echo "$LIMITS" | cut -d: -f1)
    DOWN_MBPS=$(echo "$LIMITS" | cut -d: -f2)
}

create_config() {
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
}

apply_sysctl() {
    cat > "$SYSCTL_FILE" << 'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 300
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    
    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    fi
}

write_firewall_script() {
    cat > "$FW_SCRIPT" << EOFW
#!/usr/bin/env bash
LISTEN_PORT="${LISTEN_PORT}"

iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -t mangle -F POSTROUTING 2>/dev/null || true

# تحويل كافة منافذ UDP من 1 إلى 65535 إلى بورت Hysteria الداخلي 36712
iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports \$LISTEN_PORT
iptables -I INPUT -p udp --dport 1:65535 -j ACCEPT
iptables -I INPUT -p udp --dport \$LISTEN_PORT -j ACCEPT

# إصلاح تقطيع التصفح وضبط الـ MTU
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi
exit 0
EOFW
    chmod 750 "$FW_SCRIPT"
    bash "$FW_SCRIPT"
}

create_services() {
    cat > "$SVC_FW" << EOF
[Unit]
Description=Hysteria Firewall Port Mapping
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
}

start_services() {
    systemctl enable hysteria-firewall >/dev/null 2>&1
    systemctl restart hysteria-firewall
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    
    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        msg "خدمة Hysteria تعمل بنجاح!"
    else
        err "حدث خطأ أثناء التشغيل:"
        journalctl -u hysteria-server --no-pager -n 15
        exit 1
    fi
}

show_info() {
    echo -e "\n${GREEN}${BOLD}==================================================${NC}"
    echo -e "${GREEN}${BOLD}     تم التثبيت وإعداد المدى 1-65535 بنجاح!        ${NC}"
    echo -e "${GREEN}${BOLD}==================================================${NC}"
    echo -e "  ${BOLD}UDP Server${NC} : ${CYAN}${SERVER_IP}${NC}"
    echo -e "  ${BOLD}UDP Port${NC}   : ${CYAN}1-65535${NC}"
    echo -e "  ${BOLD}Obfs${NC}       : ${CYAN}${OBFS}${NC}"
    echo -e "  ${BOLD}Auth${NC}       : ${CYAN}${AUTH_STR}${NC}"
    echo -e "  ${BOLD}Up Down${NC}    : ${CYAN}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo -e "${GREEN}${BOLD}==================================================${NC}\n"
}

# Execution
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
