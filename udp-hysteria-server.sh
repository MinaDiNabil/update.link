#!/bin/bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup Script
#  Compatible with MinaProNetVPN Tunnel App (Hysteria v1)
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
        print_err "Must run as root (sudo)"
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
    apt-get install -y -qq curl wget openssl iptables nftables conntrack > /dev/null 2>&1
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

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        print_warn "Certificate exists, skipping"
        return
    fi
    print_info "Generating certificate..."
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" \
        -out "$HYSTERIA_CERT" \
        -subj "/CN=bing.com" \
        -days 3650 2>/dev/null
    chmod 600 "$HYSTERIA_KEY"
    chmod 644 "$HYSTERIA_CERT"
    print_msg "Certificate generated"
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

    read -rp "$(echo -e "${CYAN}Auth password [default: minapronet2025]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-minapronet2025}

    read -rp "$(echo -e "${CYAN}Upload Mbps [default: 100]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-100}

    read -rp "$(echo -e "${CYAN}Download Mbps [default: 100]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-100}

    echo ""
}

create_config() {
    mkdir -p "$HYSTERIA_DIR"
    print_info "Creating configuration..."

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
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS}
}
EOF
    chmod 600 "$HYSTERIA_CONFIG"
    print_msg "Configuration created"
}

optimize_kernel() {
    print_info "Optimizing kernel..."

    # Load required modules FIRST
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true
    modprobe nf_conntrack_ipv4 2>/dev/null || true
    modprobe xt_REDIRECT 2>/dev/null || true

    cat > /etc/sysctl.d/99-hysteria-udp.conf << 'EOF'
# UDP buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# UDP memory
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# IP forward
net.ipv4.ip_forward = 1

# Conntrack (critical for port hopping)
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_udp_timeout = 12
net.netfilter.nf_conntrack_udp_timeout_stream = 35

# TCP
net.ipv4.tcp_fastopen = 3
EOF

    # Set hashsize before sysctl
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
    print_info "Creating systemd service..."

    cat > "$HYSTERIA_SERVICE" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN)
After=network.target network-online.target
Wants=network-online.target

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
# Port hopping setup - tries nftables first, falls back to iptables
# ============================================================
setup_port_hopping() {
    if [ "$USE_PORT_HOPPING" != true ]; then
        # Single port - just open it in firewall
        iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow "${LISTEN_PORT}/udp" > /dev/null 2>&1 || true
        fi
        print_msg "Single port ${LISTEN_PORT} opened"
        return
    fi

    print_info "Setting up port hopping..."

    # Method 1: Try nftables (most reliable for port hopping)
    if setup_nftables; then
        print_msg "Port hopping via nftables"
        HOPPING_METHOD="nftables"
        return
    fi

    # Method 2: Fall back to iptables
    if setup_iptables_redirect; then
        print_msg "Port hopping via iptables"
        HOPPING_METHOD="iptables"
        return
    fi

    print_err "Could not set up port hopping! Use single port ${LISTEN_PORT} in the app."
}

setup_nftables() {
    # Check if nftables is available
    if ! command -v nft &>/dev/null; then
        print_warn "nftables not available, trying iptables..."
        return 1
    fi

    print_info "Configuring nftables..."

    # Flush old hysteria rules
    nft delete table inet hysteria 2>/dev/null || true

    # Create nftables rules
    nft add table inet hysteria 2>/dev/null || return 1

    # Allow incoming UDP
    nft add chain inet hysteria input '{ type filter hook input priority 0; }' 2>/dev/null || return 1
    nft add rule inet hysteria input udp dport "${LISTEN_PORT}" accept 2>/dev/null || return 1
    nft add rule inet hysteria input udp dport "${PORT_RANGE_START}-${PORT_RANGE_END}" accept 2>/dev/null || return 1

    # NAT redirect
    nft add chain inet hysteria prerouting '{ type nat hook prerouting priority dstnat; }' 2>/dev/null || return 1
    nft add rule inet hysteria prerouting udp dport "${PORT_RANGE_START}-${PORT_RANGE_END}" redirect to ":${LISTEN_PORT}" 2>/dev/null || return 1

    # Verify
    if nft list chain inet hysteria prerouting 2>/dev/null | grep -q "redirect"; then
        # Save nftables rules
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
        systemctl enable nftables 2>/dev/null || true

        # Create restore script
        cat > "$IPTABLES_SCRIPT" << EOIPT
#!/bin/bash
# Restore nftables rules for Hysteria port hopping
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

    # nftables didn't work
    nft delete table inet hysteria 2>/dev/null || true
    return 1
}

setup_iptables_redirect() {
    print_info "Configuring iptables..."

    # Load modules
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true
    modprobe xt_REDIRECT 2>/dev/null || true

    # Clean old rules
    iptables -t nat -F PREROUTING 2>/dev/null || true

    # Allow established
    iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Open ports
    iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j ACCEPT 2>/dev/null || true

    # Redirect
    iptables -t nat -A PREROUTING -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null || return 1

    # Verify
    if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir"; then
        # Save
        if command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save > /dev/null 2>&1 || true
        fi

        # Create restore script
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

# UFW handling (separate from redirect)
setup_ufw() {
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        if [ "$USE_PORT_HOPPING" = true ]; then
            ufw allow "${PORT_RANGE_START}:${PORT_RANGE_END}/udp" > /dev/null 2>&1 || true
        else
            ufw allow "${LISTEN_PORT}/udp" > /dev/null 2>&1 || true
        fi
    fi
}

# Persist rules via rc.local
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

    # Test 1: Listening
    if ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT}"; then
        print_msg "Test 1/5: Listening on ${LISTEN_PORT}"
    else
        print_err "Test 1/5: NOT listening!"
    fi

    # Test 2: DNS
    if nslookup google.com > /dev/null 2>&1; then
        print_msg "Test 2/5: DNS OK"
    else
        print_err "Test 2/5: DNS FAILED"
    fi

    # Test 3: Internet
    if curl -s4m5 -o /dev/null http://www.google.com 2>/dev/null; then
        print_msg "Test 3/5: Internet OK"
    else
        print_warn "Test 3/5: Internet limited"
    fi

    # Test 4: Port hopping active
    if [ "$USE_PORT_HOPPING" = true ]; then
        if [ "$HOPPING_METHOD" = "nftables" ]; then
            if nft list chain inet hysteria prerouting 2>/dev/null | grep -q "redirect"; then
                print_msg "Test 4/5: Port hopping ACTIVE (nftables)"
            else
                print_err "Test 4/5: Port hopping NOT active!"
            fi
        else
            if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir"; then
                print_msg "Test 4/5: Port hopping ACTIVE (iptables)"
            else
                print_err "Test 4/5: Port hopping NOT active!"
            fi
        fi
    else
        print_msg "Test 4/5: Single port mode"
    fi

    # Test 5: Conntrack
    local CT_MAX CT_COUNT
    CT_MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "0")
    CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0")
    if [ "$CT_MAX" -gt 0 ]; then
        print_msg "Test 5/5: Conntrack ${CT_COUNT}/${CT_MAX}"
    else
        print_msg "Test 5/5: Conntrack OK"
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
    echo -e "${GREEN}${BOLD}║              Server Ready!                       ║${NC}"
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
Method:      ${HOPPING_METHOD:-direct}
=======================================
EOF
}

uninstall() {
    print_warn "Uninstalling..."
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    rm -f "$HYSTERIA_SERVICE"
    rm -f "$HYSTERIA_BIN"

    # Clean nftables
    nft delete table inet hysteria 2>/dev/null || true

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
    sed -i '/hysteria/d' /etc/rc.local 2>/dev/null || true

    print_msg "Uninstalled"
    exit 0
}

# ======================== MAIN ========================

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
fix_dns
get_config
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
