#!/usr/bin/env bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server (Clean & Fast Mode)
#  No UDP Throttling | No Conntrack Drops | OVH Safe
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
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-clean.conf"

check_root() {
    [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
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
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl wget openssl ca-certificates iptables iproute2 >/dev/null 2>&1
    
    # تعطيل UFW والجدار الناري المحلي لمنع خنق UDP
    ufw disable 2>/dev/null || true
    iptables -F
    iptables -t nat -F
}

install_hysteria() {
    local ARCH TMP
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) exit 1 ;;
    esac

    TMP=$(mktemp)
    wget -q -O "$TMP" "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${ARCH}"
    chmod 755 "$TMP"; mv -f "$TMP" "$HYSTERIA_BIN"
}

create_user() {
    if ! id "$HYSTERIA_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$HYSTERIA_USER"
    fi
}

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"; chmod 750 "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then return; fi
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" -out "$HYSTERIA_CERT" \
        -subj "/CN=hysteria.mnet" -days 3650 2>/dev/null
    chmod 640 "$HYSTERIA_KEY"; chmod 644 "$HYSTERIA_CERT"
    chown root:"$HYSTERIA_USER" "$HYSTERIA_KEY" "$HYSTERIA_CERT"
}

get_config() {
    LISTEN_PORT="36712"
    read -rp "$(echo -e "${CYAN}Obfs password [default: minapronet]: ${NC}")" OBFS
    OBFS=${OBFS:-minapronet}
    
    read -rp "$(echo -e "${CYAN}Auth password [default: 2a1d4b9896e:7823f72fcd10:16fbcee5gf]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-2a1d4b9896e:7823f72fcd10:16fbcee5gf}
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
    "up_mbps": 200,
    "down_mbps": 500,
    "disable_udp": false,
    "recv_window_conn": 16777216,
    "recv_window_client": 67108864,
    "max_conn_client": 2048,
    "disable_mtu_discovery": false
}
EOF
    chmod 640 "$HYSTERIA_CONFIG"; chown root:"$HYSTERIA_USER" "$HYSTERIA_CONFIG"
}

apply_sysctl() {
    # إعدادات النواة المباشرة لتخزين الـ Buffers بدون حدود تتبع خنقة
    cat > "$SYSCTL_FILE" << 'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.core.netdev_max_backlog = 100000
net.ipv4.ip_forward = 1
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

write_firewall_script() {
    # توجيه مباشر ومبسط جداً لحزم UDP دون فحص حالات Connection Tracking
    cat > "$FW_SCRIPT" << EOFW
#!/usr/bin/env bash
LISTEN_PORT="${LISTEN_PORT}"

iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true

# تحويل كافة المنافذ إلى البورت الداخلي مباشرة
iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports \$LISTEN_PORT
iptables -A INPUT -p udp --dport 1:65535 -j ACCEPT
iptables -A INPUT -p udp --dport \$LISTEN_PORT -j ACCEPT

exit 0
EOFW
    chmod 750 "$FW_SCRIPT"
    bash "$FW_SCRIPT"
}

create_services() {
    cat > "$SVC_FW" << EOF
[Unit]
Description=Clean UDP Firewall Direct Mapping
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${FW_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SVC_MAIN" << EOF
[Unit]
Description=Hysteria UDP Server Clean
After=network-online.target hysteria-firewall.service
Wants=network-online.target

[Service]
Type=simple
User=${HYSTERIA_USER}
Group=${HYSTERIA_USER}
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
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
}

# تشغيل خطوات الإعداد
check_root
detect_iface
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

echo -e "\n${GREEN}[✓] تم التحديث بنجاح! السيرفر يعمل الآن بنظام UDP المباشر بدون قيود.${NC}\n"
