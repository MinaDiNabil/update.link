#!/bin/bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup Script
#  Compatible with MinaProNetVPN Tunnel App (Hysteria v1)
#  For Ubuntu 18.04 / 20.04 / 22.04 / 24.04
# ============================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Paths
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
HYSTERIA_CERT="${HYSTERIA_DIR}/server.crt"
HYSTERIA_KEY="${HYSTERIA_DIR}/server.key"
HYSTERIA_SERVICE="/etc/systemd/system/hysteria-server.service"
IPTABLES_SCRIPT="${HYSTERIA_DIR}/iptables.sh"

# Internal listen port (Hysteria binds to this)
LISTEN_PORT="36712"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║     MinaProNet VPN - Hysteria UDP Server        ║"
    echo "║         Fast & Stable UDP Tunnel                ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_msg() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
print_err() { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${CYAN}[i]${NC} $1"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_err "This script must be run as root (sudo)"
        exit 1
    fi
}

get_server_ip() {
    print_info "Detecting server IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me 2>/dev/null || curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        read -rp "Enter your server IP: " SERVER_IP
    fi
    print_msg "Server IP: ${SERVER_IP}"
}

install_deps() {
    print_info "Installing dependencies..."
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y -qq curl wget openssl iptables > /dev/null 2>&1
    print_msg "Dependencies installed"
}

install_hysteria() {
    if [ -f "$HYSTERIA_BIN" ]; then
        print_warn "Hysteria binary already exists, updating..."
    fi

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
        print_err "Failed to download Hysteria"
        exit 1
    fi
    chmod +x "$HYSTERIA_BIN"

    # Verify binary is executable (v1 uses -h, not "version")
    if ! "$HYSTERIA_BIN" -h > /dev/null 2>&1; then
        print_err "Downloaded binary is not working"
        exit 1
    fi
    print_msg "Hysteria v1 installed at ${HYSTERIA_BIN}"
}

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"

    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        print_warn "Certificate already exists, skipping"
        return
    fi

    print_info "Generating self-signed certificate..."
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" \
        -out "$HYSTERIA_CERT" \
        -subj "/CN=bing.com" \
        -days 3650 2>/dev/null
    chmod 600 "$HYSTERIA_KEY"
    chmod 644 "$HYSTERIA_CERT"
    print_msg "Certificate generated (valid 10 years)"
}

get_config() {
    echo ""
    echo -e "${BOLD}=== Server Configuration ===${NC}"
    echo ""

    echo -e "${CYAN}Port range for the app. Examples: 443 / 1-65535 / 20000-50000${NC}"
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

    read -rp "$(echo -e "${CYAN}Auth password [default: minapronet2025]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-minapronet2025}

    read -rp "$(echo -e "${CYAN}Upload Mbps [default: 100]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-100}

    read -rp "$(echo -e "${CYAN}Download Mbps [default: 100]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-100}

    echo ""
}

# ============================================================
#  Hysteria v1 Server Config
#  Must match client: auth_str, obfs, recv_window
# ============================================================
create_config() {
    mkdir -p "$HYSTERIA_DIR"
    print_info "Creating server configuration..."

    cat > "$HYSTERIA_CONFIG" << EOF
{
    "listen": ":${LISTEN_PORT}",
    "cert": "${HYSTERIA_CERT}",
    "key": "${HYSTERIA_KEY}",
    "obfs": "${OBFS}",
    "auth": {
        "mode": "password",
        "config": {
            "password": "${AUTH_STR}"
        }
    },
    "resolver": "udp://8.8.8.8:53",
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS},
    "recv_window_conn": 3407872,
    "recv_window_client": 13631488,
    "max_conn_client": 4096,
    "disable_mtu_discovery": false
}
EOF
    chmod 600 "$HYSTERIA_CONFIG"

    print_msg "Configuration created"
}

optimize_kernel() {
    print_info "Optimizing kernel for UDP..."

    cat > /etc/sysctl.d/99-hysteria-udp.conf << 'EOF'
# UDP buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Socket backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# UDP memory
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# IP forwarding
net.ipv4.ip_forward = 1

# TCP fast open
net.ipv4.tcp_fastopen = 3
EOF

    sysctl -p /etc/sysctl.d/99-hysteria-udp.conf > /dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1 || true
        print_msg "BBR enabled"
    fi

    print_msg "Kernel optimized"
}

create_service() {
    print_info "Creating systemd service..."

    cat > "$HYSTERIA_SERVICE" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_msg "Systemd service created"
}

setup_firewall() {
    print_info "Configuring firewall..."

    # Detect main interface
    MAIN_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
    if [ -z "$MAIN_IFACE" ]; then
        MAIN_IFACE="eth0"
    fi
    print_info "Interface: ${MAIN_IFACE}"

    # Clean old hysteria iptables rules first
    clean_iptables_rules

    # Allow established connections (critical!)
    iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Open listen port
    iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true

    if [ "$USE_PORT_HOPPING" = true ]; then
        print_info "Port hopping: ${PORT_RANGE_START}-${PORT_RANGE_END} -> ${LISTEN_PORT}..."

        # Open port range
        iptables -I INPUT -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j ACCEPT 2>/dev/null || true

        # Redirect ONLY external interface, NOT loopback (prevents DNS redirect loop)
        iptables -t nat -A PREROUTING -i "$MAIN_IFACE" -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null || true

        # UFW
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow "${PORT_RANGE_START}:${PORT_RANGE_END}/udp" > /dev/null 2>&1 || true
        fi

        print_msg "Port hopping configured"
    else
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow "${LISTEN_PORT}/udp" > /dev/null 2>&1 || true
        fi
    fi

    # Save iptables for reboot persistence
    save_iptables_rules

    print_msg "Firewall configured"
}

clean_iptables_rules() {
    # Remove old NAT rules related to hysteria
    iptables -t nat -F PREROUTING 2>/dev/null || true
}

save_iptables_rules() {
    # Create script to restore rules on reboot
    cat > "$IPTABLES_SCRIPT" << EOIPT
#!/bin/bash
# Restore Hysteria iptables rules
iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -p udp --dport ${LISTEN_PORT} -j ACCEPT
EOIPT

    if [ "$USE_PORT_HOPPING" = true ]; then
        cat >> "$IPTABLES_SCRIPT" << EOIPT
iptables -I INPUT -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j ACCEPT
iptables -t nat -A PREROUTING -i ${MAIN_IFACE} -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j REDIRECT --to-ports ${LISTEN_PORT}
EOIPT
    fi
    chmod +x "$IPTABLES_SCRIPT"

    # Save with iptables-save
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    # Try netfilter-persistent
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save > /dev/null 2>&1 || true
    fi

    # Add to rc.local as fallback
    if [ ! -f /etc/rc.local ] || ! grep -q "hysteria" /etc/rc.local 2>/dev/null; then
        echo "bash ${IPTABLES_SCRIPT}" >> /etc/rc.local 2>/dev/null || true
        chmod +x /etc/rc.local 2>/dev/null || true
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
        print_err "Failed to start! Logs:"
        echo ""
        journalctl -u hysteria-server --no-pager -n 20
        exit 1
    fi
}

# Verify the server can actually relay traffic
verify_server() {
    echo ""
    print_info "Running connectivity tests..."

    # Test 1: Check server is listening
    if ss -ulnp | grep -q ":${LISTEN_PORT}"; then
        print_msg "Test 1/4: Hysteria listening on port ${LISTEN_PORT}"
    else
        print_err "Test 1/4: NOT listening on port ${LISTEN_PORT}!"
    fi

    # Test 2: DNS resolution from server
    if nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1 || dig google.com +short > /dev/null 2>&1; then
        print_msg "Test 2/4: DNS resolution working"
    else
        print_warn "Test 2/4: DNS might not work! Trying to fix..."
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
        print_info "Set DNS to 8.8.8.8 / 1.1.1.1"
    fi

    # Test 3: Internet connectivity from server
    if curl -s4m5 -o /dev/null -w "%{http_code}" http://www.google.com 2>/dev/null | grep -q "200\|301\|302"; then
        print_msg "Test 3/4: Internet connectivity OK"
    else
        print_warn "Test 3/4: Server may have limited internet access"
    fi

    # Test 4: Check iptables are not blocking outbound
    local OUTBOUND_POLICY
    OUTBOUND_POLICY=$(iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    if [ "$OUTBOUND_POLICY" = "ACCEPT" ] || [ -z "$OUTBOUND_POLICY" ]; then
        print_msg "Test 4/4: Outbound traffic allowed"
    else
        print_warn "Test 4/4: OUTPUT policy is ${OUTBOUND_POLICY}, adding ACCEPT rules..."
        iptables -I OUTPUT -j ACCEPT 2>/dev/null || true
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

    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║         Server Ready!                            ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}=== App Settings (MinaProNet VPN) ===${NC}"
    echo ""
    echo -e "  ${CYAN}UDP Server :${NC}  ${BOLD}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}UDP Port   :${NC}  ${BOLD}${APP_PORT}${NC}"
    echo -e "  ${CYAN}Obfs       :${NC}  ${BOLD}${OBFS}${NC}"
    echo -e "  ${CYAN}Auth       :${NC}  ${BOLD}${AUTH_STR}${NC}"
    echo -e "  ${CYAN}UpDown     :${NC}  ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
    echo -e "${BOLD}=== Management ===${NC}"
    echo ""
    echo -e "  ${YELLOW}Status :${NC}  systemctl status hysteria-server"
    echo -e "  ${YELLOW}Logs   :${NC}  journalctl -u hysteria-server -f"
    echo -e "  ${YELLOW}Restart:${NC}  systemctl restart hysteria-server"
    echo -e "  ${YELLOW}Remove :${NC}  bash udp-hysteria-server.sh --uninstall"
    echo ""

    cat > "${HYSTERIA_DIR}/connection-info.txt" << EOF
=======================================
 MinaProNet VPN - Connection Details
=======================================
UDP Server:  ${SERVER_IP}
UDP Port:    ${APP_PORT}
Obfs:        ${OBFS}
Auth:        ${AUTH_STR}
UpDown:      ${UP_MBPS}:${DOWN_MBPS}
Internal:    ${LISTEN_PORT}
=======================================
EOF
}

uninstall() {
    print_warn "Uninstalling Hysteria server..."
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    rm -f "$HYSTERIA_SERVICE"
    rm -f "$HYSTERIA_BIN"

    # Clean iptables
    iptables -t nat -F PREROUTING 2>/dev/null || true
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    rm -rf "$HYSTERIA_DIR"
    rm -f /etc/sysctl.d/99-hysteria-udp.conf
    sysctl --system > /dev/null 2>&1 || true
    systemctl daemon-reload

    # Clean rc.local
    sed -i '/hysteria/d' /etc/rc.local 2>/dev/null || true

    print_msg "Uninstalled successfully"
    exit 0
}

# ========================
#       MAIN
# ========================

if [ "$1" = "--uninstall" ]; then
    check_root
    uninstall
fi

print_banner
check_root
get_server_ip
install_deps
install_hysteria
generate_cert
get_config
create_config
optimize_kernel
create_service
setup_firewall
start_service
verify_server
show_info

echo -e "${GREEN}${BOLD}Done! Server is ready.${NC}"
echo ""
