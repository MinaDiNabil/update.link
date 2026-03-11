#!/bin/bash

#=====================================================
#  UDP Hysteria V1 - MinaProNet VPN Service
#  Server: udp-hysteria.minapronetvpn.com
#  Ports: 1-65535 | Stable & Fast
#=====================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

UDP_SERVER="udp-hysteria.minapronetvpn.com"
UDP_PORT="36712"
UDP_PORT_RANGE="1-65535"
UDP_OBFS="minapronet"
UDP_AUTH="mina:udp:hysteria"
UDP_PROTOCOL="udp"
UP_SPEED=100
DOWN_SPEED=100

HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
HYSTERIA_SERVICE="/etc/systemd/system/hysteria-server.service"
CERT_DIR="${HYSTERIA_DIR}/certs"

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         MinaProNet - UDP Hysteria V1 Server              ║"
    echo "║   Server: udp-hysteria.minapronetvpn.com                 ║"
    echo "║   Ports: 1-65535 | Stable • Fast • No Drops              ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${CYAN}[➤]${NC} $1"; }
separator() { echo -e "${BLUE}─────────────────────────────────────────────────${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root!"
        exit 1
    fi
}

# ═══════════════════════════════════════
#  FIX DNS FIRST - Critical Step
# ═══════════════════════════════════════
fix_dns() {
    log_step "Fixing DNS resolution..."

    # Test if DNS works
    if nslookup github.com > /dev/null 2>&1 || ping -c1 -W2 github.com > /dev/null 2>&1; then
        log_info "DNS is working"
        return 0
    fi

    log_warn "DNS not working, applying fix..."

    # Stop systemd-resolved if blocking
    if systemctl is-active --quiet systemd-resolved; then
        log_warn "Stopping systemd-resolved..."
        systemctl stop systemd-resolved 2>/dev/null
        systemctl disable systemd-resolved 2>/dev/null
    fi

    # Backup old resolv.conf
    [[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null

    # Remove symlink if exists
    rm -f /etc/resolv.conf 2>/dev/null

    # Write fresh DNS servers
    cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

    chmod 644 /etc/resolv.conf

    # Make it immutable so nothing overwrites it
    chattr +i /etc/resolv.conf 2>/dev/null

    # Wait for DNS to apply
    sleep 2

    # Test again
    if nslookup github.com > /dev/null 2>&1 || ping -c1 -W3 github.com > /dev/null 2>&1; then
        log_info "DNS fixed successfully!"
        return 0
    fi

    # Try alternative: add DNS to interface config
    if command -v resolvectl &>/dev/null; then
        resolvectl dns eth0 8.8.8.8 1.1.1.1 2>/dev/null
        resolvectl dns ens3 8.8.8.8 1.1.1.1 2>/dev/null
        sleep 1
    fi

    # Final test
    if nslookup github.com > /dev/null 2>&1 || host github.com > /dev/null 2>&1; then
        log_info "DNS fixed via resolvectl!"
        return 0
    fi

    log_warn "DNS may still have issues. Trying with direct IP fallback..."
    return 1
}

get_server_ip() {
    log_step "Detecting server IP..."

    # Method 1: curl with DNS working
    SERVER_IP=$(curl -s4 --connect-timeout 5 ifconfig.me 2>/dev/null)

    # Method 2: alternative services
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(curl -s4 --connect-timeout 5 icanhazip.com 2>/dev/null)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(curl -s4 --connect-timeout 5 ip.sb 2>/dev/null)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(curl -s4 --connect-timeout 5 ipinfo.io/ip 2>/dev/null)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(curl -s4 --connect-timeout 5 api.ipify.org 2>/dev/null)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(curl -s4 --connect-timeout 5 checkip.amazonaws.com 2>/dev/null)

    # Method 3: wget fallback
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(wget -qO- --timeout=5 ifconfig.me 2>/dev/null)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(wget -qO- --timeout=5 icanhazip.com 2>/dev/null)

    # Method 4: dig
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null)

    # Method 5: from network interface
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    fi

    # Method 6: hostname
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

    # Last resort: ask user
    if [[ -z "$SERVER_IP" ]]; then
        log_warn "Could not auto-detect IP"
        read -rp "$(echo -e ${CYAN}"Enter your server IP: "${NC})" SERVER_IP
    fi

    # Trim whitespace
    SERVER_IP=$(echo "$SERVER_IP" | tr -d '[:space:]')

    if [[ -z "$SERVER_IP" ]]; then
        log_error "No server IP provided!"
        exit 1
    fi

    log_info "Server IP: ${SERVER_IP}"
}

check_system() {
    log_step "Checking system requirements..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  HYSTERIA_ARCH="amd64" ;;
        aarch64) HYSTERIA_ARCH="arm64" ;;
        armv7l)  HYSTERIA_ARCH="arm" ;;
        i686)    HYSTERIA_ARCH="386" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    log_info "Architecture: ${ARCH} (${HYSTERIA_ARCH})"
    log_info "OS: Linux"
}

install_dependencies() {
    log_step "Installing dependencies..."
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq curl wget openssl iptables net-tools jq dnsutils > /dev/null 2>&1
    log_info "Dependencies installed"
}

install_hysteria() {
    log_step "Downloading Hysteria V1..."

    local URLS=(
        "https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-${HYSTERIA_ARCH}"
        "https://download.hysteria.network/app/latest/hysteria-linux-${HYSTERIA_ARCH}"
        "https://objects.githubusercontent.com/github-production-release-asset-2e65be/457516794/hysteria-linux-${HYSTERIA_ARCH}"
    )

    [[ -f "$HYSTERIA_BIN" ]] && cp "$HYSTERIA_BIN" "${HYSTERIA_BIN}.bak"

    local DOWNLOADED=0

    for URL in "${URLS[@]}"; do
        log_step "Trying: ${URL}..."

        # Try wget first
        wget -q --show-progress --timeout=30 -O "$HYSTERIA_BIN" "$URL" 2>/dev/null
        if [[ -f "$HYSTERIA_BIN" ]] && [[ -s "$HYSTERIA_BIN" ]]; then
            DOWNLOADED=1
            break
        fi

        # Try curl
        curl -fsSL --connect-timeout 30 -o "$HYSTERIA_BIN" "$URL" 2>/dev/null
        if [[ -f "$HYSTERIA_BIN" ]] && [[ -s "$HYSTERIA_BIN" ]]; then
            DOWNLOADED=1
            break
        fi
    done

    if [[ $DOWNLOADED -eq 0 ]]; then
        log_error "All download attempts failed!"
        log_warn "Please check your server's internet/DNS connection:"
        echo -e "  ${YELLOW}1)${NC} Test DNS:   ${WHITE}nslookup github.com${NC}"
        echo -e "  ${YELLOW}2)${NC} Test ping:  ${WHITE}ping -c3 8.8.8.8${NC}"
        echo -e "  ${YELLOW}3)${NC} Fix DNS:    ${WHITE}echo 'nameserver 8.8.8.8' > /etc/resolv.conf${NC}"
        echo -e "  ${YELLOW}4)${NC} Then retry: ${WHITE}./hysteria-v1-install.sh${NC}"
        exit 1
    fi

    chmod +x "$HYSTERIA_BIN"
    log_info "Hysteria V1 downloaded successfully"
}

generate_certificates() {
    log_step "Generating SSL certificates for ${UDP_SERVER}..."
    mkdir -p "$CERT_DIR"
    openssl ecparam -genkey -name prime256v1 -out "${CERT_DIR}/private.key" 2>/dev/null
    openssl req -new -x509 -key "${CERT_DIR}/private.key" -out "${CERT_DIR}/cert.crt" -days 3650 -subj "/CN=${UDP_SERVER}/O=MinaProNet/C=US" 2>/dev/null
    chmod 600 "${CERT_DIR}/private.key"
    chmod 644 "${CERT_DIR}/cert.crt"
    log_info "SSL certificates generated (valid 10 years)"
}

optimize_system() {
    log_step "Applying system optimizations..."

    cat > /etc/sysctl.d/99-hysteria.conf << 'EOF'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.ipv4.udp_mem = 262144 524288 1048576
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
fs.file-max = 1048576
fs.nr_open = 1048576
net.ipv6.conf.all.forwarding = 1
EOF

    sysctl -p /etc/sysctl.d/99-hysteria.conf > /dev/null 2>&1

    cat > /etc/security/limits.d/99-hysteria.conf << 'EOF'
*       soft    nofile      1048576
*       hard    nofile      1048576
root    soft    nofile      1048576
root    hard    nofile      1048576
EOF

    modprobe tcp_bbr 2>/dev/null
    modprobe nf_conntrack 2>/dev/null
    log_info "System optimizations applied"
}

setup_port_forwarding() {
    log_step "Setting up port forwarding (All UDP 1-65535)..."
    local LP=$1

    iptables -t nat -F HYSTERIA_PREROUTING 2>/dev/null
    iptables -t nat -X HYSTERIA_PREROUTING 2>/dev/null
    iptables -t nat -N HYSTERIA_PREROUTING 2>/dev/null
    iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport 1:$((LP - 1)) -j REDIRECT --to-ports "$LP"
    iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport $((LP + 1)):65535 -j REDIRECT --to-ports "$LP"
    iptables -t nat -D PREROUTING -j HYSTERIA_PREROUTING 2>/dev/null
    iptables -t nat -A PREROUTING -j HYSTERIA_PREROUTING
    iptables-save > /etc/iptables.rules 2>/dev/null

    cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c "iptables-restore < /etc/iptables.rules 2>/dev/null || true"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable iptables-restore.service > /dev/null 2>&1
    log_info "All UDP ports (1-65535) → port ${LP}"
}

configure_hysteria() {
    log_step "Configuring Hysteria V1..."
    separator
    echo -e "  ${CYAN}UDP Server:${NC}  ${WHITE}${UDP_SERVER}${NC}"
    echo -e "  ${CYAN}Server IP:${NC}   ${WHITE}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}UDP Port:${NC}    ${WHITE}${UDP_PORT_RANGE}${NC}"
    echo -e "  ${CYAN}UDP Obfs:${NC}    ${WHITE}${UDP_OBFS}${NC}"
    echo -e "  ${CYAN}UDP Auth:${NC}    ${WHITE}${UDP_AUTH}${NC}"
    separator

    mkdir -p "$HYSTERIA_DIR"

    cat > "$HYSTERIA_CONFIG" << HYSTCONFIG
{
    "listen": ":${UDP_PORT}",
    "protocol": "${UDP_PROTOCOL}",
    "cert": "${CERT_DIR}/cert.crt",
    "key": "${CERT_DIR}/private.key",
    "obfs": "${UDP_OBFS}",
    "up_mbps": ${UP_SPEED},
    "down_mbps": ${DOWN_SPEED},
    "auth": {
        "mode": "password",
        "config": {
            "password": "${UDP_AUTH}"
        }
    },
    "alpn": "h3",
    "recv_window_conn": 67108864,
    "recv_window_client": 167772160,
    "max_conn_client": 4096,
    "disable_mtu_discovery": false,
    "resolver": "udp://8.8.8.8:53",
    "resolve_preference": "46"
}
HYSTCONFIG

    log_info "Configuration saved"
}

create_service() {
    log_step "Creating systemd service..."

    cat > "$HYSTERIA_SERVICE" << 'EOF'
[Unit]
Description=MinaProNet Hysteria V1 Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json --log-level info
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=512000
StandardOutput=append:/var/log/hysteria.log
StandardError=append:/var/log/hysteria.log
NoNewPrivileges=false
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
Nice=-10
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service created"
}

create_watchdog() {
    log_step "Creating watchdog..."

    cat > /usr/local/bin/hysteria-watchdog.sh << 'EOF'
#!/bin/bash
while true; do
    if ! systemctl is-active --quiet hysteria-server; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hysteria DOWN - restarting..." >> /var/log/hysteria-watchdog.log
        systemctl restart hysteria-server
        sleep 3
        if systemctl is-active --quiet hysteria-server; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hysteria restarted OK" >> /var/log/hysteria-watchdog.log
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: restart failed!" >> /var/log/hysteria-watchdog.log
        fi
    fi
    LP=$(jq -r '.listen' /etc/hysteria/config.json 2>/dev/null | tr -d ':')
    if [[ -n "$LP" ]]; then
        if ! iptables -t nat -L HYSTERIA_PREROUTING -n 2>/dev/null | grep -q "$LP"; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] iptables missing - restoring..." >> /var/log/hysteria-watchdog.log
            iptables-restore < /etc/iptables.rules 2>/dev/null
        fi
    fi
    sleep 30
done
EOF

    chmod +x /usr/local/bin/hysteria-watchdog.sh

    cat > /etc/systemd/system/hysteria-watchdog.service << 'EOF'
[Unit]
Description=Hysteria Watchdog
After=hysteria-server.service

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria-watchdog.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-watchdog.service > /dev/null 2>&1
    log_info "Watchdog created"
}

create_management() {
    log_step "Creating management command..."

    cat > /usr/local/bin/hysteria-manage << 'MANAGE'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'
UDP_SERVER="udp-hysteria.minapronetvpn.com"

get_ip() {
    local IP=""
    IP=$(curl -s4 --connect-timeout 5 ifconfig.me 2>/dev/null)
    [[ -z "$IP" ]] && IP=$(curl -s4 --connect-timeout 5 icanhazip.com 2>/dev/null)
    [[ -z "$IP" ]] && IP=$(curl -s4 --connect-timeout 5 ip.sb 2>/dev/null)
    [[ -z "$IP" ]] && IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    [[ -z "$IP" ]] && IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "$IP"
}

show_status() {
    echo -e "\n${CYAN}═══ MinaProNet Hysteria V1 Status ═══${NC}\n"
    systemctl is-active --quiet hysteria-server && echo -e "  Service:  ${GREEN}● Running${NC}" || echo -e "  Service:  ${RED}● Stopped${NC}"
    systemctl is-active --quiet hysteria-watchdog && echo -e "  Watchdog: ${GREEN}● Active${NC}" || echo -e "  Watchdog: ${RED}● Inactive${NC}"
    CFG="/etc/hysteria/config.json"
    if [[ -f "$CFG" ]]; then
        IP=$(get_ip)
        echo -e "  UDP Server: ${WHITE}${UDP_SERVER}${NC}"
        echo -e "  Server IP:  ${WHITE}${IP}${NC}"
        echo -e "  Port Range: ${GREEN}1-65535 (All UDP)${NC}"
        echo -e "  UDP Obfs:   ${WHITE}$(jq -r '.obfs' $CFG)${NC}"
        echo -e "  UDP Auth:   ${WHITE}$(jq -r '.auth.config.password' $CFG)${NC}"
        echo -e "  Speed:      ${WHITE}↑$(jq -r '.up_mbps' $CFG) / ↓$(jq -r '.down_mbps' $CFG) Mbps${NC}"
    fi
    echo ""
}

show_info() {
    CFG="/etc/hysteria/config.json"
    [[ ! -f "$CFG" ]] && echo -e "${RED}Config not found!${NC}" && return
    IP=$(get_ip)
    PORT=$(jq -r '.listen' "$CFG" | tr -d ':')
    PROTO=$(jq -r '.protocol' "$CFG")
    OBFS=$(jq -r '.obfs' "$CFG")
    AUTH=$(jq -r '.auth.config.password' "$CFG")
    UP=$(jq -r '.up_mbps' "$CFG")
    DOWN=$(jq -r '.down_mbps' "$CFG")

    echo -e "\n${CYAN}══════════════════════════════════════════${NC}"
    echo -e "${CYAN}    MinaProNet - Connection Information    ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════${NC}\n"
    echo -e "  ${WHITE}UDP Server:${NC}  ${UDP_SERVER}"
    echo -e "  ${WHITE}Server IP:${NC}   ${IP}"
    echo -e "  ${WHITE}UDP Port:${NC}    1-65535 ${GREEN}(any port works)${NC}"
    echo -e "  ${WHITE}Protocol:${NC}    ${PROTO}"
    echo -e "  ${WHITE}UDP Obfs:${NC}    ${OBFS}"
    echo -e "  ${WHITE}UDP Auth:${NC}    ${AUTH}"
    echo -e "  ${WHITE}Upload:${NC}      ${UP} Mbps"
    echo -e "  ${WHITE}Download:${NC}    ${DOWN} Mbps"
    echo -e "  ${WHITE}ALPN:${NC}        h3"
    echo -e "  ${WHITE}Insecure:${NC}    true"

    echo -e "\n${CYAN}═══ Client Config ═══${NC}\n"
    cat << CLIENTCFG
{
    "server": "${UDP_SERVER}:${PORT}",
    "protocol": "${PROTO}",
    "obfs": "${OBFS}",
    "auth_str": "${AUTH}",
    "alpn": "h3",
    "up_mbps": ${UP},
    "down_mbps": ${DOWN},
    "server_name": "${UDP_SERVER}",
    "insecure": true,
    "recv_window_conn": 67108864,
    "recv_window": 167772160,
    "fast_open": true,
    "lazy_start": true,
    "hop_interval": 60
}
CLIENTCFG

    echo -e "\n${CYAN}═══ Hysteria V1 URI ═══${NC}\n"
    echo -e "  hysteria://${UDP_SERVER}:${PORT}?protocol=${PROTO}&auth=${AUTH}&obfsParam=${OBFS}&peer=${UDP_SERVER}&insecure=1&upmbps=${UP}&downmbps=${DOWN}&alpn=h3#MinaProNet-Hysteria"
    echo -e "\n${CYAN}═══ URI with IP ═══${NC}\n"
    echo -e "  hysteria://${IP}:${PORT}?protocol=${PROTO}&auth=${AUTH}&obfsParam=${OBFS}&peer=${UDP_SERVER}&insecure=1&upmbps=${UP}&downmbps=${DOWN}&alpn=h3#MinaProNet-Hysteria-IP"
    echo ""
}

change_auth() {
    CFG="/etc/hysteria/config.json"
    read -rp "New UDP Auth: " V
    [[ -n "$V" ]] && { TMP=$(mktemp); jq --arg v "$V" '.auth.config.password=$v' "$CFG" > "$TMP" && mv "$TMP" "$CFG"; systemctl restart hysteria-server; echo -e "${GREEN}UDP Auth → ${V} — restarted${NC}"; }
}

change_obfs() {
    CFG="/etc/hysteria/config.json"
    read -rp "New UDP Obfs: " V
    [[ -n "$V" ]] && { TMP=$(mktemp); jq --arg v "$V" '.obfs=$v' "$CFG" > "$TMP" && mv "$TMP" "$CFG"; systemctl restart hysteria-server; echo -e "${GREEN}UDP Obfs → ${V} — restarted${NC}"; }
}

change_port() {
    CFG="/etc/hysteria/config.json"
    OLD=$(jq -r '.listen' "$CFG" | tr -d ':')
    read -rp "New port [current: ${OLD}]: " V
    if [[ -n "$V" ]]; then
        TMP=$(mktemp); jq --arg v ":${V}" '.listen=$v' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
        iptables -t nat -F HYSTERIA_PREROUTING 2>/dev/null
        iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport 1:$((V-1)) -j REDIRECT --to-ports "$V"
        iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport $((V+1)):65535 -j REDIRECT --to-ports "$V"
        iptables-save > /etc/iptables.rules 2>/dev/null
        systemctl restart hysteria-server
        echo -e "${GREEN}Port → ${V} — restarted${NC}"
    fi
}

change_speed() {
    CFG="/etc/hysteria/config.json"
    read -rp "Upload (Mbps): " U; read -rp "Download (Mbps): " D
    if [[ -n "$U" ]] && [[ -n "$D" ]]; then
        TMP=$(mktemp); jq --argjson u "$U" --argjson d "$D" '.up_mbps=$u|.down_mbps=$d' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
        systemctl restart hysteria-server
        echo -e "${GREEN}Speed → ↑${U}/↓${D} Mbps — restarted${NC}"
    fi
}

uninstall_all() {
    echo -e "${RED}Remove Hysteria V1 completely?${NC}"
    read -rp "(y/N): " C
    if [[ "$C" =~ ^[Yy]$ ]]; then
        systemctl stop hysteria-server hysteria-watchdog 2>/dev/null
        systemctl disable hysteria-server hysteria-watchdog 2>/dev/null
        rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-watchdog.service /etc/systemd/system/iptables-restore.service
        rm -f /usr/local/bin/hysteria /usr/local/bin/hysteria-watchdog.sh /usr/local/bin/hysteria-manage
        rm -rf /etc/hysteria
        rm -f /var/log/hysteria.log /var/log/hysteria-watchdog.log
        rm -f /etc/sysctl.d/99-hysteria.conf /etc/security/limits.d/99-hysteria.conf
        iptables -t nat -D PREROUTING -j HYSTERIA_PREROUTING 2>/dev/null
        iptables -t nat -F HYSTERIA_PREROUTING 2>/dev/null
        iptables -t nat -X HYSTERIA_PREROUTING 2>/dev/null
        rm -f /etc/iptables.rules
        systemctl daemon-reload
        echo -e "${GREEN}Uninstalled successfully${NC}"
        exit 0
    fi
}

while true; do
    echo -e "\n${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   MinaProNet Hysteria V1 Management        ║${NC}"
    echo -e "${CYAN}║   udp-hysteria.minapronetvpn.com           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}\n"
    echo -e "  ${GREEN} 1)${NC} Show Status"
    echo -e "  ${GREEN} 2)${NC} Connection Info & Client Config"
    echo -e "  ${GREEN} 3)${NC} Start Service"
    echo -e "  ${GREEN} 4)${NC} Stop Service"
    echo -e "  ${GREEN} 5)${NC} Restart Service"
    echo -e "  ${GREEN} 6)${NC} View Logs"
    echo -e "  ${GREEN} 7)${NC} Change UDP Auth"
    echo -e "  ${GREEN} 8)${NC} Change UDP Obfs"
    echo -e "  ${GREEN} 9)${NC} Change Port"
    echo -e "  ${GREEN}10)${NC} Change Speed"
    echo -e "  ${RED}11)${NC} Uninstall"
    echo -e "  ${YELLOW} 0)${NC} Exit"
    echo ""
    read -rp "Select: " OPT

    case "$OPT" in
        1)  show_status ;;
        2)  show_info ;;
        3)  systemctl start hysteria-server hysteria-watchdog && echo -e "${GREEN}Started${NC}" ;;
        4)  systemctl stop hysteria-server hysteria-watchdog && echo -e "${YELLOW}Stopped${NC}" ;;
        5)  systemctl restart hysteria-server && echo -e "${GREEN}Restarted${NC}" ;;
        6)  echo ""; tail -50 /var/log/hysteria.log 2>/dev/null || journalctl -u hysteria-server -n 50; echo "" ;;
        7)  change_auth ;;
        8)  change_obfs ;;
        9)  change_port ;;
        10) change_speed ;;
        11) uninstall_all ;;
        0)  exit 0 ;;
        *)  echo -e "${RED}Invalid option${NC}" ;;
    esac
done
MANAGE

    chmod +x /usr/local/bin/hysteria-manage
    log_info "Management: hysteria-manage"
}

start_services() {
    log_step "Starting Hysteria V1..."
    systemctl enable hysteria-server > /dev/null 2>&1
    systemctl start hysteria-server
    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        log_info "Hysteria V1 is RUNNING!"
        systemctl start hysteria-watchdog
    else
        log_error "Failed to start! Check: journalctl -u hysteria-server"
    fi
}

show_result() {
    echo ""
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║   MinaProNet Hysteria V1 - Installed Successfully!   ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}UDP Server:${NC}  ${WHITE}${UDP_SERVER}${NC}"
    echo -e "  ${CYAN}Server IP:${NC}   ${WHITE}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}UDP Port:${NC}    ${WHITE}${UDP_PORT_RANGE}${NC} ${GREEN}(All ports!)${NC}"
    echo -e "  ${CYAN}UDP Obfs:${NC}    ${WHITE}${UDP_OBFS}${NC}"
    echo -e "  ${CYAN}UDP Auth:${NC}    ${WHITE}${UDP_AUTH}${NC}"
    echo -e "  ${CYAN}Speed:${NC}       ${WHITE}↑${UP_SPEED} / ↓${DOWN_SPEED} Mbps${NC}"
    echo ""
    separator
    echo ""
    echo -e "  ${YELLOW}Manage:${NC} ${WHITE}hysteria-manage${NC}"
    echo -e "  ${YELLOW}Config:${NC} ${WHITE}/etc/hysteria/config.json${NC}"
    echo -e "  ${YELLOW}Logs:${NC}   ${WHITE}/var/log/hysteria.log${NC}"
    echo ""
    echo -e "  ${CYAN}Hysteria V1 URI:${NC}"
    echo -e "  ${WHITE}hysteria://${UDP_SERVER}:${UDP_PORT}?protocol=${UDP_PROTOCOL}&auth=${UDP_AUTH}&obfsParam=${UDP_OBFS}&peer=${UDP_SERVER}&insecure=1&upmbps=${UP_SPEED}&downmbps=${DOWN_SPEED}&alpn=h3#MinaProNet-Hysteria${NC}"
    echo ""
    echo -e "  ${CYAN}URI with IP:${NC}"
    echo -e "  ${WHITE}hysteria://${SERVER_IP}:${UDP_PORT}?protocol=${UDP_PROTOCOL}&auth=${UDP_AUTH}&obfsParam=${UDP_OBFS}&peer=${UDP_SERVER}&insecure=1&upmbps=${UP_SPEED}&downmbps=${DOWN_SPEED}&alpn=h3#MinaProNet-Hysteria-IP${NC}"
    echo ""
    separator
}

# ═══════════════════════════════════════
#  Main Installation Flow
# ═══════════════════════════════════════

main() {
    print_banner
    check_root
    fix_dns
    get_server_ip
    check_system
    separator
    install_dependencies
    fix_dns
    install_hysteria
    generate_certificates
    optimize_system
    configure_hysteria
    setup_port_forwarding "$UDP_PORT"
    create_service
    create_watchdog
    create_management
    separator
    start_services
    show_result
}

main "$@"
