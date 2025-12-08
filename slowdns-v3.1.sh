#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
#  SlowDNS FINAL v3.1 - Fixed DNS Issue
# ═══════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

NS_DOMAIN="dnstt-servers.minapronetvpn.com"
DNSTT_DIR="/etc/slowdns"
DNSTT_BIN="/usr/local/bin/dnstt-server"

show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   ███████╗██╗      ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗   ║
    ║   ██╔════╝██║     ██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝   ║
    ║   ███████╗██║     ██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗   ║
    ║   ╚════██║██║     ██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║   ║
    ║   ███████║███████╗╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║   ║
    ║   ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ║
    ║                                                                   ║
    ║                      ⚡ FINAL v3.1 ⚡                              ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Run as root: sudo bash $0${NC}"
        exit 1
    fi
}

check_os() {
    source /etc/os-release 2>/dev/null
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        echo -e "${RED}[ERROR] Ubuntu/Debian required!${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] OS: $ID $VERSION_ID${NC}"
}

# ═══════════════════════════════════════════════════════════════════
#  FIX PORT 53 - WITHOUT BREAKING DNS
# ═══════════════════════════════════════════════════════════════════
fix_port_53() {
    echo -e "${BLUE}[*] Configuring port 53...${NC}"
    
    # Check if systemd-resolved is using port 53 on 127.0.0.53
    if ss -tulpn 2>/dev/null | grep -q "127.0.0.53:53"; then
        echo -e "${YELLOW}[!] Configuring systemd-resolved to free port 53...${NC}"
        
        # Create resolved.conf.d directory
        mkdir -p /etc/systemd/resolved.conf.d
        
        # Configure resolved to not listen on port 53
        cat > /etc/systemd/resolved.conf.d/slowdns.conf << 'EOF'
[Resolve]
DNSStubListener=no
DNS=8.8.8.8 8.8.4.4 1.1.1.1
EOF
        
        # Restart resolved
        systemctl restart systemd-resolved 2>/dev/null
        
        # Fix resolv.conf symlink
        rm -f /etc/resolv.conf
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        
        sleep 2
    fi
    
    # Verify DNS still works
    if ! ping -c 1 google.com &>/dev/null; then
        echo -e "${YELLOW}[!] Fixing DNS...${NC}"
        rm -f /etc/resolv.conf
        echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
    fi
    
    echo -e "${GREEN}[✓] Port 53 configured!${NC}"
}

optimize_kernel() {
    echo -e "${BLUE}[*] Optimizing kernel...${NC}"
    
    cat > /etc/sysctl.d/99-slowdns.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_default = 2097152
net.core.rmem_max = 67108864
net.core.wmem_default = 2097152
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 2097152 67108864
net.ipv4.tcp_wmem = 4096 2097152 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
vm.swappiness = 1
fs.file-max = 2097152
EOF

    sysctl -p /etc/sysctl.d/99-slowdns.conf > /dev/null 2>&1
    modprobe tcp_bbr 2>/dev/null
    echo -e "${GREEN}[✓] Kernel optimized!${NC}"
}

optimize_limits() {
    echo -e "${BLUE}[*] Optimizing limits...${NC}"
    
    cat > /etc/security/limits.d/99-slowdns.conf << 'EOF'
*       soft    nofile      2097152
*       hard    nofile      2097152
root    soft    nofile      2097152
root    hard    nofile      2097152
EOF

    ulimit -n 2097152 2>/dev/null
    echo -e "${GREEN}[✓] Limits optimized!${NC}"
}

optimize_ssh() {
    echo -e "${BLUE}[*] Optimizing SSH...${NC}"
    
    mkdir -p /etc/ssh/sshd_config.d
    rm -f /etc/ssh/sshd_config.d/*slowdns*.conf
    
    cat > /etc/ssh/sshd_config.d/slowdns.conf << 'EOF'
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com
HostKeyAlgorithms ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512
UseDNS no
TCPKeepAlive yes
ClientAliveInterval 15
ClientAliveCountMax 3
Compression yes
PermitTunnel yes
AllowTcpForwarding yes
GatewayPorts yes
MaxStartups 200:30:300
MaxSessions 200
EOF

    if ! grep -q "Include /etc/ssh/sshd_config.d/\*.conf" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    fi

    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo -e "${GREEN}[✓] SSH optimized!${NC}"
}

install_deps() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    
    apt-get update -y > /dev/null 2>&1
    apt-get install -y wget curl git unzip net-tools dnsutils iptables > /dev/null 2>&1
    
    if ! command -v go &> /dev/null; then
        echo -e "${BLUE}[*] Installing Go...${NC}"
        wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile 2>/dev/null
    
    echo -e "${GREEN}[✓] Dependencies installed!${NC}"
}

install_dnstt() {
    echo -e "${BLUE}[*] Building dnstt-server...${NC}"
    
    mkdir -p $DNSTT_DIR
    cd /tmp
    rm -rf dnstt dnstt-master dnstt.zip
    
    # Try git clone first
    if git clone https://www.bamsoftware.com/git/dnstt.git 2>/dev/null; then
        echo -e "${GREEN}[✓] Cloned from bamsoftware${NC}"
    elif git clone https://github.com/plinss/dnstt.git 2>/dev/null; then
        echo -e "${GREEN}[✓] Cloned from github${NC}"
    else
        # Fallback to wget
        echo -e "${YELLOW}[!] Git failed, trying wget...${NC}"
        wget -q https://github.com/plinss/dnstt/archive/refs/heads/master.zip -O dnstt.zip
        if [[ -f "dnstt.zip" ]]; then
            unzip -q dnstt.zip
            mv dnstt-master dnstt
            echo -e "${GREEN}[✓] Downloaded via wget${NC}"
        else
            echo -e "${RED}[ERROR] Failed to download dnstt!${NC}"
            echo -e "${YELLOW}Check your internet connection:${NC}"
            echo -e "  ping -c 2 google.com"
            exit 1
        fi
    fi
    
    if [[ ! -d "dnstt" ]]; then
        echo -e "${RED}[ERROR] dnstt folder not found!${NC}"
        exit 1
    fi
    
    cd dnstt/dnstt-server
    export PATH=$PATH:/usr/local/go/bin
    go build -ldflags="-s -w" -o dnstt-server 2>/dev/null
    
    if [[ -f "dnstt-server" ]]; then
        mv dnstt-server $DNSTT_BIN
        chmod +x $DNSTT_BIN
        echo -e "${GREEN}[✓] dnstt-server installed!${NC}"
    else
        echo -e "${RED}[ERROR] Build failed!${NC}"
        exit 1
    fi
    
    cd /
    rm -rf /tmp/dnstt /tmp/dnstt.zip /tmp/dnstt-master
}

setup_keys() {
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    KEY CONFIGURATION${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Generate NEW keys (first time)"
    echo -e "  ${GREEN}[2]${NC} Enter SAVED keys (reinstallation)"
    echo ""
    read -p "Select [1/2]: " key_option
    
    case $key_option in
        2) use_saved_keys ;;
        *) generate_keys ;;
    esac
}

generate_keys() {
    echo -e "${BLUE}[*] Generating keypair...${NC}"
    
    KEYS=$($DNSTT_BIN -gen-key 2>&1)
    PRIV_KEY=$(echo "$KEYS" | grep -i "privkey" | awk '{print $2}')
    PUB_KEY=$(echo "$KEYS" | grep -i "pubkey" | awk '{print $2}')
    
    if [[ -z "$PRIV_KEY" ]] || [[ -z "$PUB_KEY" ]]; then
        echo -e "${RED}[ERROR] Key generation failed!${NC}"
        exit 1
    fi
    
    echo "$PRIV_KEY" > $DNSTT_DIR/server.key
    echo "$PUB_KEY" > $DNSTT_DIR/server.pub
    chmod 600 $DNSTT_DIR/server.key
    
    FINAL_PUB_KEY="$PUB_KEY"
    FINAL_PRIV_KEY="$PRIV_KEY"
    
    echo -e "${GREEN}[✓] Keys generated!${NC}"
}

use_saved_keys() {
    echo ""
    echo -e "${YELLOW}Enter PRIVATE Key:${NC}"
    read -p "> " input_privkey
    
    echo -e "${YELLOW}Enter PUBLIC Key:${NC}"
    read -p "> " input_pubkey
    
    if [[ -z "$input_privkey" ]] || [[ -z "$input_pubkey" ]]; then
        echo -e "${RED}[ERROR] Keys cannot be empty!${NC}"
        exit 1
    fi
    
    echo "$input_privkey" > $DNSTT_DIR/server.key
    echo "$input_pubkey" > $DNSTT_DIR/server.pub
    chmod 600 $DNSTT_DIR/server.key
    
    FINAL_PUB_KEY="$input_pubkey"
    FINAL_PRIV_KEY="$input_privkey"
    
    echo -e "${GREEN}[✓] Keys saved!${NC}"
}

create_services() {
    echo -e "${BLUE}[*] Creating services...${NC}"
    
    # UDP 5300
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS (UDP 5300)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Nice=-20
LimitNOFILE=2097152
ExecStart=$DNSTT_BIN -udp :5300 -privkey-file $DNSTT_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

    # UDP 53
    cat > /etc/systemd/system/slowdns-53.service << EOF
[Unit]
Description=SlowDNS (UDP 53)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Nice=-20
LimitNOFILE=2097152
ExecStart=$DNSTT_BIN -udp :53 -privkey-file $DNSTT_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

    # UDP 5353
    cat > /etc/systemd/system/slowdns-5353.service << EOF
[Unit]
Description=SlowDNS (UDP 5353)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Nice=-20
LimitNOFILE=2097152
ExecStart=$DNSTT_BIN -udp :5353 -privkey-file $DNSTT_DIR/server.key $NS_DOMAIN 127.0.0.1:22
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slowdns slowdns-53 slowdns-5353 > /dev/null 2>&1
    
    echo -e "${GREEN}[✓] Services created!${NC}"
}

setup_firewall() {
    echo -e "${BLUE}[*] Configuring firewall...${NC}"
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp > /dev/null 2>&1
        ufw allow 53/udp > /dev/null 2>&1
        ufw allow 5300/udp > /dev/null 2>&1
        ufw allow 5353/udp > /dev/null 2>&1
    fi
    
    iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p udp --dport 5353 -j ACCEPT 2>/dev/null
    iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null
    
    echo -e "${GREEN}[✓] Firewall configured!${NC}"
}

create_menu() {
    echo -e "${BLUE}[*] Creating menu...${NC}"
    
    cat > /usr/local/bin/slowdns << 'MENU_EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

NS_DOMAIN="dnstt-servers.minapronetvpn.com"
DNSTT_DIR="/etc/slowdns"

show_menu() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                SlowDNS Control Panel                         ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo "║  [1] Start All          [5] View Logs                        ║"
    echo "║  [2] Stop All           [6] Connection Info                  ║"
    echo "║  [3] Restart All        [7] Show BOTH Keys                   ║"
    echo "║  [4] Check Status       [8] Uninstall                        ║"
    echo "║                         [0] Exit                             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    read -p "Select: " opt
    
    case $opt in
        1) systemctl start slowdns slowdns-53 slowdns-5353; echo -e "${GREEN}Started!${NC}"; sleep 2; show_menu ;;
        2) systemctl stop slowdns slowdns-53 slowdns-5353; echo -e "${GREEN}Stopped!${NC}"; sleep 2; show_menu ;;
        3) systemctl restart slowdns slowdns-53 slowdns-5353; echo -e "${GREEN}Restarted!${NC}"; sleep 2; show_menu ;;
        4) status_check ;;
        5) journalctl -u slowdns -u slowdns-53 -n 50 --no-pager; read -p "Enter..."; show_menu ;;
        6) show_info ;;
        7) show_keys ;;
        8) uninstall ;;
        0) exit 0 ;;
        *) show_menu ;;
    esac
}

status_check() {
    echo ""
    for svc in slowdns slowdns-53 slowdns-5353; do
        if systemctl is-active --quiet $svc; then
            echo -e "  ${GREEN}●${NC} $svc: ${GREEN}Running${NC}"
        else
            echo -e "  ${RED}●${NC} $svc: ${RED}Stopped${NC}"
        fi
    done
    echo ""
    ss -tulpn | grep dnstt 2>/dev/null
    read -p "Enter..."; show_menu
}

show_info() {
    IP=$(curl -s ifconfig.me 2>/dev/null)
    PUB=$(cat $DNSTT_DIR/server.pub 2>/dev/null)
    clear
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    📱 APP SETTINGS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "  DNS/NS      : $NS_DOMAIN"
    echo -e "  DNS Server  : 8.8.8.8"
    echo -e "  DNS Port    : 53 / 5300 / 5353"
    echo -e "  Server IP   : $IP"
    echo -e "  SSH Port    : 22"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    PUBLIC KEY${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$PUB${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}⚠️  Enable EDNS0 in app!${NC}"
    read -p "Enter..."; show_menu
}

show_keys() {
    clear
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}   ⚠️  SAVE THESE KEYS FOR REINSTALLATION!${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}PRIVATE KEY:${NC}"
    echo -e "${GREEN}$(cat $DNSTT_DIR/server.key)${NC}"
    echo ""
    echo -e "${YELLOW}PUBLIC KEY:${NC}"
    echo -e "${GREEN}$(cat $DNSTT_DIR/server.pub)${NC}"
    echo ""
    read -p "Enter..."; show_menu
}

uninstall() {
    read -p "Remove SlowDNS? (y/n): " c
    if [[ "$c" == "y" ]]; then
        systemctl stop slowdns slowdns-53 slowdns-5353
        systemctl disable slowdns slowdns-53 slowdns-5353
        rm -f /etc/systemd/system/slowdns*.service
        rm -rf /etc/slowdns
        rm -f /usr/local/bin/dnstt-server /usr/local/bin/slowdns
        rm -f /etc/sysctl.d/99-slowdns.conf
        rm -f /etc/security/limits.d/99-slowdns.conf
        rm -f /etc/ssh/sshd_config.d/slowdns.conf
        rm -f /etc/systemd/resolved.conf.d/slowdns.conf
        systemctl daemon-reload
        systemctl restart systemd-resolved 2>/dev/null
        echo -e "${GREEN}Uninstalled!${NC}"
        exit 0
    fi
    show_menu
}

show_menu
MENU_EOF

    chmod +x /usr/local/bin/slowdns
    echo -e "${GREEN}[✓] Menu created!${NC}"
}

show_final() {
    IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com)
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ⚡ Installation Complete! ⚡                         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║      ⚠️  SAVE THESE KEYS FOR FUTURE REINSTALLATION!  ⚠️            ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    🔐 PRIVATE KEY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$FINAL_PRIV_KEY${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    🔑 PUBLIC KEY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$FINAL_PUB_KEY${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    📱 APP SETTINGS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  DNS/NS      : $NS_DOMAIN"
    echo -e "  DNS Server  : ${CYAN}8.8.8.8${NC}"
    echo -e "  DNS Port    : ${CYAN}53${NC} / 5300 / 5353"
    echo -e "  Server IP   : $IP"
    echo -e "  SSH Port    : 22"
    echo -e "  ${RED}⚠️ EDNS0     : ENABLE IT!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${PURPLE}Command:${NC} ${GREEN}slowdns${NC}"
    echo ""
    
    echo -e "${YELLOW}Status:${NC}"
    for svc in slowdns slowdns-53 slowdns-5353; do
        if systemctl is-active --quiet $svc; then
            echo -e "  ${GREEN}●${NC} $svc: ${GREEN}Running${NC}"
        else
            echo -e "  ${RED}●${NC} $svc: ${RED}Stopped${NC}"
        fi
    done
    echo ""
}

main() {
    show_banner
    check_root
    check_os
    
    install_deps
    fix_port_53
    optimize_kernel
    optimize_limits
    optimize_ssh
    install_dnstt
    setup_keys
    create_services
    setup_firewall
    create_menu
    
    echo -e "${BLUE}[*] Starting services...${NC}"
    systemctl start slowdns slowdns-53 slowdns-5353 2>/dev/null
    sleep 3
    
    show_final
}

main
