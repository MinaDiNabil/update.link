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
    apt-get install -y -qq curl wget openssl iptables conntrack > /dev/null 2>&1
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
        print_err "Failed to download Hysteria"
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

    print_info "Generating self-signed certificate..."
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" \
        -out "$HYSTERIA_CERT" \
        -subj "/CN=bing.com" \
        -days 3650 2>/dev/null
    chmod 600 "$HYSTERIA_KEY"
    chmod 644 "$HYSTERIA_CERT"
    print_msg "Certificate generated"
}

# Fix system DNS FIRST (before anything else needs it)
fix_dns() {
    print_info "Ensuring DNS works..."

    # Test if DNS works
    if ! nslookup google.com > /dev/null 2>&1; then
        print_warn "DNS broken, fixing..."
        # Backup
        cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true

        # Disable systemd-resolved if it's causing issues
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            mkdir -p /etc/systemd/resolved.conf.d
            cat > /etc/systemd/resolved.conf.d/dns.conf << 'EOF'
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4 1.0.0.1
EOF
            systemctl restart systemd-resolved 2>/dev/null || true
        fi

        # Direct fix
        cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    fi

    # Verify
    if nslookup google.com > /dev/null 2>&1; then
        print_msg "DNS working"
    else
        print_warn "DNS may still have issues"
    fi
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
#  MINIMAL Hysteria v1 config - only required fields
#  Let Hysteria use its own defaults for recv_window etc.
#  This prevents flow control mismatch with client
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
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS}
}
EOF
    chmod 600 "$HYSTERIA_CONFIG"
    print_msg "Configuration created (minimal stable config)"
}

optimize_kernel() {
    print_info "Optimizing kernel for UDP..."

    cat > /etc/sysctl.d/99-hysteria-udp.conf << 'EOF'
# === UDP buffers (critical for Hysteria stability) ===
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# === Socket backlog ===
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# === UDP memory ===
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# === IP forwarding ===
net.ipv4.ip_forward = 1

# === Conntrack tuning (CRITICAL for port hopping stability) ===
# Without this, conntrack table fills up and packets get dropped
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_buckets = 262144
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 120

# === TCP optimizations ===
net.ipv4.tcp_fastopen = 3
EOF

    # Load conntrack module first (needed for nf_conntrack sysctl)
    modprobe nf_conntrack 2>/dev/null || true

    sysctl -p /etc/sysctl.d/99-hysteria-udp.conf > /dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1 || true
        print_msg "BBR enabled"
    fi

    print_msg "Kernel optimized (conntrack max=1M)"
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

    # Clean old NAT rules
    iptables -t nat -F PREROUTING 2>/dev/null || true

    # Allow established connections
    iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Open listen port
    iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true

    if [ "$USE_PORT_HOPPING" = true ]; then
        print_info "Port hopping: ${PORT_RANGE_START}-${PORT_RANGE_END} -> ${LISTEN_PORT}..."

        # Open port range
        iptables -I INPUT -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j ACCEPT 2>/dev/null || true

        # Redirect ALL incoming UDP in range to listen port
        # Safe because: DNS uses system resolv.conf (not affected by PREROUTING)
        # and outgoing traffic goes through OUTPUT chain, not PREROUTING
        iptables -t nat -A PREROUTING -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null || true

        # UFW
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow "${PORT_RANGE_START}:${PORT_RANGE_END}/udp" > /dev/null 2>&1 || true
        fi

        # Verify the rule was applied
        if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports ${LISTEN_PORT}"; then
            print_msg "Port hopping rule ACTIVE"
        else
            print_err "Port hopping rule FAILED - trying alternative method..."
            # Fallback: use DNAT
            iptables -t nat -A PREROUTING -p udp --dport "${PORT_RANGE_START}:${PORT_RANGE_END}" -j DNAT --to-destination "127.0.0.1:${LISTEN_PORT}" 2>/dev/null || true
        fi
    else
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow "${LISTEN_PORT}/udp" > /dev/null 2>&1 || true
        fi
    fi

    # Save rules
    save_iptables_rules

    print_msg "Firewall configured"
}

save_iptables_rules() {
    # Create restore script
    cat > "$IPTABLES_SCRIPT" << EOIPT
#!/bin/bash
modprobe nf_conntrack 2>/dev/null
iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -p udp --dport ${LISTEN_PORT} -j ACCEPT
EOIPT

    if [ "$USE_PORT_HOPPING" = true ]; then
        cat >> "$IPTABLES_SCRIPT" << EOIPT
iptables -I INPUT -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j ACCEPT
iptables -t nat -A PREROUTING -p udp --dport ${PORT_RANGE_START}:${PORT_RANGE_END} -j REDIRECT --to-ports ${LISTEN_PORT}
EOIPT
    fi
    chmod +x "$IPTABLES_SCRIPT"

    # Persist
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save > /dev/null 2>&1 || true
    fi

    # rc.local fallback
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
        journalctl -u hysteria-server --no-pager -n 20
        exit 1
    fi
}

verify_server() {
    echo ""
    print_info "Running connectivity tests..."

    # Test 1: Listening
    if ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT}"; then
        print_msg "Test 1/5: Listening on port ${LISTEN_PORT}"
    else
        print_err "Test 1/5: NOT listening on ${LISTEN_PORT}!"
    fi

    # Test 2: DNS
    if nslookup google.com > /dev/null 2>&1; then
        print_msg "Test 2/5: DNS working"
    else
        print_err "Test 2/5: DNS FAILED"
    fi

    # Test 3: Internet
    if curl -s4m5 -o /dev/null http://www.google.com 2>/dev/null; then
        print_msg "Test 3/5: Internet OK"
    else
        print_warn "Test 3/5: Internet may be limited"
    fi

    # Test 4: Outbound not blocked
    local OUT_POLICY
    OUT_POLICY=$(iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+')
    if [ "$OUT_POLICY" = "ACCEPT" ] || [ -z "$OUT_POLICY" ]; then
        print_msg "Test 4/5: Outbound traffic OK"
    else
        print_warn "Test 4/5: Fixing outbound policy..."
        iptables -I OUTPUT -j ACCEPT 2>/dev/null || true
    fi

    # Test 5: Conntrack table
    local CT_MAX CT_COUNT
    CT_MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "0")
    CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0")
    if [ "$CT_MAX" -gt 0 ]; then
        local CT_PERCENT=$((CT_COUNT * 100 / CT_MAX))
        print_msg "Test 5/5: Conntrack ${CT_COUNT}/${CT_MAX} (${CT_PERCENT}% used)"
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
fix_dns
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
