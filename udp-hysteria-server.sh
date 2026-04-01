#!/bin/bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup Script
#  Compatible with MinaProNetVPN Tunnel App (Hysteria v1)
#  For Ubuntu 18.04 / 20.04 / 22.04 / 24.04
# ============================================================

set -e

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

# Check root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_err "This script must be run as root (sudo)"
        exit 1
    fi
}

# Detect server IP
get_server_ip() {
    SERVER_IP=$(curl -s4 ifconfig.me 2>/dev/null || curl -s4 ip.sb 2>/dev/null || curl -s4 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IP" ]; then
        print_err "Could not detect server IP"
        read -rp "Enter your server IP: " SERVER_IP
    fi
}

# Install dependencies
install_deps() {
    print_info "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq curl wget openssl iptables > /dev/null 2>&1
    print_msg "Dependencies installed"
}

# Download Hysteria v1 binary
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

    wget -q --show-progress -O "$HYSTERIA_BIN" "$DOWNLOAD_URL"
    chmod +x "$HYSTERIA_BIN"
    print_msg "Hysteria v1 installed at ${HYSTERIA_BIN}"
}

# Generate self-signed certificate
generate_cert() {
    mkdir -p "$HYSTERIA_DIR"
    print_info "Generating self-signed certificate..."
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$HYSTERIA_KEY" \
        -out "$HYSTERIA_CERT" \
        -subj "/CN=minapronet.com" \
        -days 3650 \
        2>/dev/null
    chmod 600 "$HYSTERIA_KEY"
    chmod 644 "$HYSTERIA_CERT"
    print_msg "Certificate generated (valid for 10 years)"
}

# Get user configuration
get_config() {
    echo ""
    echo -e "${BOLD}=== Server Configuration ===${NC}"
    echo ""

    # Port
    read -rp "$(echo -e "${CYAN}Enter UDP port [default: 443]: ${NC}")" PORT
    PORT=${PORT:-443}

    # Obfuscation
    read -rp "$(echo -e "${CYAN}Enter obfuscation password (obfs) [default: minapronet]: ${NC}")" OBFS
    OBFS=${OBFS:-minapronet}

    # Auth password
    read -rp "$(echo -e "${CYAN}Enter auth password [default: minapronet2025]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-minapronet2025}

    # Speed limits
    read -rp "$(echo -e "${CYAN}Upload speed limit in Mbps [default: 100]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-100}

    read -rp "$(echo -e "${CYAN}Download speed limit in Mbps [default: 100]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-100}

    echo ""
}

# Create server config
create_config() {
    mkdir -p "$HYSTERIA_DIR"
    print_info "Creating server configuration..."

    cat > "$HYSTERIA_CONFIG" << EOF
{
    "listen": ":${PORT}",
    "protocol": "udp",
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
    "down_mbps": ${DOWN_MBPS},
    "recv_window_conn": 3407872,
    "recv_window_client": 13631488,
    "max_conn_client": 4096,
    "disable_mtu_discovery": false,
    "resolve_preference": "46"
}
EOF
    chmod 600 "$HYSTERIA_CONFIG"
    print_msg "Configuration created at ${HYSTERIA_CONFIG}"
}

# Optimize kernel for UDP performance
optimize_kernel() {
    print_info "Optimizing kernel for UDP performance..."

    local SYSCTL_CONF="/etc/sysctl.d/99-hysteria-udp.conf"
    cat > "$SYSCTL_CONF" << 'EOF'
# ============================================
# Hysteria UDP Server - Kernel Optimizations
# ============================================

# Increase UDP buffer sizes (critical for stability)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Increase socket backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# UDP memory tuning
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# Enable IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Disable ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Connection tracking for better NAT
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# TCP optimizations (for mixed traffic)
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF

    sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1 || true

    # Enable BBR if available
    if modprobe tcp_bbr 2>/dev/null; then
        print_msg "BBR congestion control enabled"
    fi

    print_msg "Kernel optimizations applied"
}

# Create systemd service
create_service() {
    print_info "Creating systemd service..."

    cat > "$HYSTERIA_SERVICE" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN)
Documentation=https://hysteria.network
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
StandardOutput=journal
StandardError=journal

# Performance settings
Nice=-10
CPUSchedulingPolicy=rr
CPUSchedulingPriority=50

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${HYSTERIA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_msg "Systemd service created"
}

# Configure firewall
setup_firewall() {
    print_info "Configuring firewall..."

    # Open port with iptables (works on all Ubuntu)
    iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    ip6tables -I INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true

    # If UFW is active, add rule
    if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
        ufw allow "${PORT}/udp" > /dev/null 2>&1
        print_msg "UFW rule added for port ${PORT}/udp"
    fi

    print_msg "Firewall configured - port ${PORT}/udp open"
}

# Start the service
start_service() {
    print_info "Starting Hysteria server..."
    systemctl enable hysteria-server > /dev/null 2>&1
    systemctl restart hysteria-server

    sleep 2

    if systemctl is-active --quiet hysteria-server; then
        print_msg "Hysteria server is running!"
    else
        print_err "Failed to start server. Check: journalctl -u hysteria-server -f"
        exit 1
    fi
}

# Display connection info
show_info() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║       Server Installed Successfully!             ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}=== App Configuration (MinaProNet VPN) ===${NC}"
    echo ""
    echo -e "  ${CYAN}UDP Server:${NC}   ${BOLD}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}UDP Port:${NC}     ${BOLD}${PORT}${NC}"
    echo -e "  ${CYAN}Obfs:${NC}         ${BOLD}${OBFS}${NC}"
    echo -e "  ${CYAN}Auth:${NC}         ${BOLD}${AUTH_STR}${NC}"
    echo -e "  ${CYAN}UpDown:${NC}       ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
    echo -e "${BOLD}=== Server Management Commands ===${NC}"
    echo ""
    echo -e "  ${YELLOW}Status:${NC}    systemctl status hysteria-server"
    echo -e "  ${YELLOW}Stop:${NC}      systemctl stop hysteria-server"
    echo -e "  ${YELLOW}Start:${NC}     systemctl start hysteria-server"
    echo -e "  ${YELLOW}Restart:${NC}   systemctl restart hysteria-server"
    echo -e "  ${YELLOW}Logs:${NC}      journalctl -u hysteria-server -f"
    echo -e "  ${YELLOW}Uninstall:${NC} bash $0 --uninstall"
    echo ""

    # Save connection info
    cat > "${HYSTERIA_DIR}/connection-info.txt" << EOF
=======================================
 MinaProNet VPN - Connection Details
=======================================
UDP Server:  ${SERVER_IP}
UDP Port:    ${PORT}
Obfs:        ${OBFS}
Auth:        ${AUTH_STR}
UpDown:      ${UP_MBPS}:${DOWN_MBPS}
=======================================
EOF
    print_info "Connection info saved to ${HYSTERIA_DIR}/connection-info.txt"
    echo ""
}

# Uninstall
uninstall() {
    print_warn "Uninstalling Hysteria server..."
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    rm -f "$HYSTERIA_SERVICE"
    rm -f "$HYSTERIA_BIN"
    rm -rf "$HYSTERIA_DIR"
    rm -f /etc/sysctl.d/99-hysteria-udp.conf
    sysctl --system > /dev/null 2>&1
    systemctl daemon-reload
    print_msg "Hysteria server uninstalled successfully"
    exit 0
}

# Multi-port support (port hopping)
setup_multiport() {
    local MAIN_PORT="$1"

    read -rp "$(echo -e "${CYAN}Enable port hopping (multi-port)? [y/N]: ${NC}")" ENABLE_MULTIPORT
    if [[ "$ENABLE_MULTIPORT" =~ ^[Yy]$ ]]; then
        read -rp "$(echo -e "${CYAN}Port range start [default: 20000]: ${NC}")" PORT_START
        PORT_START=${PORT_START:-20000}
        read -rp "$(echo -e "${CYAN}Port range end [default: 50000]: ${NC}")" PORT_END
        PORT_END=${PORT_END:-50000}

        print_info "Setting up port hopping (${PORT_START}-${PORT_END} -> ${MAIN_PORT})..."

        # Redirect port range to main port using iptables
        iptables -t nat -A PREROUTING -p udp --dport "${PORT_START}:${PORT_END}" -j REDIRECT --to-ports "$MAIN_PORT" 2>/dev/null || true
        ip6tables -t nat -A PREROUTING -p udp --dport "${PORT_START}:${PORT_END}" -j REDIRECT --to-ports "$MAIN_PORT" 2>/dev/null || true

        # Open port range in firewall
        iptables -I INPUT -p udp --dport "${PORT_START}:${PORT_END}" -j ACCEPT 2>/dev/null || true
        ip6tables -I INPUT -p udp --dport "${PORT_START}:${PORT_END}" -j ACCEPT 2>/dev/null || true

        if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
            ufw allow "${PORT_START}:${PORT_END}/udp" > /dev/null 2>&1
        fi

        # Persist iptables rules
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save > /dev/null 2>&1
        else
            apt-get install -y -qq iptables-persistent > /dev/null 2>&1 || true
            netfilter-persistent save > /dev/null 2>&1 || true
        fi

        print_msg "Port hopping enabled: ${PORT_START}-${PORT_END} -> ${MAIN_PORT}"
        echo -e "  ${CYAN}App UDP Port:${NC} ${BOLD}${PORT_START}-${PORT_END}${NC} (use this range in the app)"
    fi
}

# ========================
#       MAIN SCRIPT
# ========================

# Handle --uninstall flag
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
setup_multiport "$PORT"
start_service
show_info

echo -e "${GREEN}${BOLD}Done! Your Hysteria UDP server is ready.${NC}"
echo ""
