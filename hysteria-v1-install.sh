#!/bin/bash
# ============================================================
#  MinaProNet - Hysteria V1 Install Script
#  Optimized for: Max Speed + Zero Disconnections
# ============================================================

PORT_UDP='5666'
SUB_DOMAIN=udp-hysteria.minapronetvpn.com
server_ip=$(curl -s https://api.ipify.org)
timedatectl set-timezone Asia/Riyadh

# ============================================================
# [1] INSTALL DEPENDENCIES
# ============================================================
install_require () {
  clear
  echo '[*] Installing dependencies...'
  export DEBIAN_FRONTEND=noninteractive
  apt update -y
  apt install -y gnupg openssl iptables socat
  apt install -y netcat-openbsd php neofetch vnstat
  apt install -y screen gnutls-bin python3
  apt install -y dos2unix nano unzip jq net-tools
  apt install -y build-essential curl wget
}

# ============================================================
# [2] KERNEL & NETWORK OPTIMIZATION (BBR + UDP Buffers)
# ============================================================
optimize_kernel () {
  clear
  echo '[*] Optimizing kernel for maximum UDP performance...'

  modprobe tcp_bbr 2>/dev/null
  echo "tcp_bbr" >> /etc/modules-load.d/modules.conf

  cat > /etc/sysctl.d/99-hysteria-performance.conf << 'SYSCTL'
# ---- BBR Congestion Control ----
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ---- UDP Buffers (64MB) ----
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 26214400
net.core.wmem_default = 26214400
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535

# ---- UDP Specific ----
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# ---- UDP Conntrack Timeout (no disconnects) ----
net.netfilter.nf_conntrack_udp_timeout = 300
net.netfilter.nf_conntrack_udp_timeout_stream = 300
net.netfilter.nf_conntrack_generic_timeout = 300
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000

# ---- IP Forwarding ----
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.eth0.rp_filter = 0

# ---- TCP Optimization ----
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# ---- File Descriptors ----
fs.file-max = 1000000
SYSCTL

  sysctl -p /etc/sysctl.d/99-hysteria-performance.conf

  cat > /etc/security/limits.d/99-hysteria.conf << 'LIMITS'
* soft nofile 1000000
* hard nofile 1000000
* soft nproc  65535
* hard nproc  65535
root soft nofile 1000000
root hard nofile 1000000
LIMITS

  modprobe nf_conntrack
  echo "nf_conntrack" >> /etc/modules-load.d/modules.conf
}

# ============================================================
# [3] INSTALL HYSTERIA V1 BINARY
# ============================================================
install_hysteria () {
  clear
  echo '[*] Installing Hysteria v1.3.5...'
  mkdir -p /etc/hysteria

  ARCH=$(uname -m)
  if [ "$ARCH" = "x86_64" ]; then
    BIN="hysteria-linux-amd64"
  elif [ "$ARCH" = "aarch64" ]; then
    BIN="hysteria-linux-arm64"
  else
    BIN="hysteria-linux-amd64"
  fi

  wget -N --no-check-certificate -q \
    -O /usr/local/bin/hysteria \
    "https://github.com/HyNetwork/hysteria/releases/download/v1.3.5/${BIN}"
  chmod +x /usr/local/bin/hysteria

  cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria VPN Server v1 - MinaProNet
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1000000
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=always
RestartSec=2s
StandardOutput=journal
StandardError=journal
WatchdogSec=30s

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria-server
}

# ============================================================
# [4] HYSTERIA V1 CONFIG (optimized)
# ============================================================
modify_hysteria () {
  clear
  echo '[*] Writing optimized Hysteria config...'
  rm -f /etc/hysteria/config.json

  cat > /etc/hysteria/config.json << 'HCONFIG'
{
  "listen": ":5666",
  "cert": "/etc/hysteria/hysteria.crt",
  "key": "/etc/hysteria/hysteria.key",

  "up_mbps": 1000,
  "down_mbps": 1000,

  "disable_udp": false,
  "obfs": "minapronet",

  "auth": {
    "mode": "passwords",
    "config": ["mina:udp:hysteria", "minapronetdev"]
  },

  "recv_window_conn": 15728640,
  "recv_window_client": 67108864,
  "max_conn_client": 4096,

  "alpn": "h3",
  "resolve_preference": "4",

  "idle_timeout": 90,
  "keepalive_period": 10
}
HCONFIG

  chmod 600 /etc/hysteria/config.json
}

# ============================================================
# [5] SSL CERTIFICATE
# ============================================================
install_letsencrypt () {
  clear
  echo '[*] Installing SSL certificate...'
  apt remove apache2 -y 2>/dev/null
  echo "$SUB_DOMAIN" > /root/domain
  domain=$(cat /root/domain)

  curl https://get.acme.sh | sh -s email=firenetdev@gmail.com
  ~/.acme.sh/acme.sh --register-account -m firenetdev@gmail.com --server zerossl
  ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256
  ~/.acme.sh/acme.sh --installcert -d "${domain}" \
    --fullchainpath /etc/hysteria/hysteria.crt \
    --keypath /etc/hysteria/hysteria.key --ecc

  chmod 644 /etc/hysteria/hysteria.crt
  chmod 600 /etc/hysteria/hysteria.key
}

# ============================================================
# [6] FIREWALL
# ============================================================
install_firewall_kvm () {
  clear
  echo '[*] Configuring firewall...'

  iptables -F
  iptables -X
  iptables -t nat -F

  iptables -t nat -A PREROUTING -i eth0 -p udp --dport 20000:50000 -j DNAT --to-destination :5666
  iptables -A INPUT -p udp --dport 5666 -j ACCEPT
  iptables -A INPUT -p tcp --dport 5666 -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  iptables -A INPUT -p udp --dport 20000:50000 -j ACCEPT

  iptables-save > /etc/iptables_rules.v4
  ip6tables-save > /etc/iptables_rules.v6
}

# ============================================================
# [7] SQUID PROXY
# ============================================================
install_squid () {
  clear
  echo '[*] Installing Squid proxy...'
  apt install -y squid
  cd /etc/squid/ || exit
  rm -f squid.conf

  SERVER_IP=$(ip route get 8.8.8.8 | awk '/src/ {f=NR} f&&NR-1==f' RS=" ")
  cat > /etc/squid/squid.conf << SQUID
acl SSH dst ${SERVER_IP}
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT
http_access allow SSH
http_access deny all
http_port 8080
http_port 8181
http_port 9090
visible_hostname MinaProNet-Proxy
SQUID

  service squid restart
}

# ============================================================
# [8] WATCHDOG - monitors & restarts Hysteria automatically
# ============================================================
install_watchdog () {
  cat > /usr/local/bin/hysteria-watchdog.sh << 'WATCHDOG'
#!/bin/bash
if ! systemctl is-active --quiet hysteria-server; then
  echo "$(date): Hysteria down, restarting..." >> /var/log/hysteria-watchdog.log
  systemctl restart hysteria-server
fi
WATCHDOG

  chmod +x /usr/local/bin/hysteria-watchdog.sh
  (crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/hysteria-watchdog.sh") | crontab -
}

# ============================================================
# [9] RC.LOCAL + BOOT PERSISTENCE
# ============================================================
install_rclocal () {
  cat > /etc/systemd/system/firenet.service << 'SERVICE'
[Unit]
Description=MinaProNet firenet service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

  cat > /etc/rc.local << 'RCLOCAL'
#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
sysctl -p /etc/sysctl.d/99-hysteria-performance.conf
systemctl restart hysteria-server
exit 0
RCLOCAL

  chmod +x /etc/rc.local
  systemctl daemon-reload
  systemctl enable firenet
  systemctl start firenet.service
}

# ============================================================
# [10] START & SHOW STATUS
# ============================================================
start_service () {
  clear
  echo '[*] Starting services...'

  systemctl daemon-reload
  systemctl restart hysteria-server
  sleep 3

  (crontab -l 2>/dev/null; echo "7 0 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null 2>&1") | sort -u | crontab -
  systemctl restart cron

  STATUS=$(systemctl is-active hysteria-server)

  clear
  echo '=================================================='
  echo '    MinaProNet - HYSTERIA V1 Ready!'
  echo '=================================================='
  echo ""
  echo " [IP]           : $server_ip"
  echo " [Port]         : 5666"
  echo " [Obfs]         : minapronet"
  echo " [Passwords]    : mina:udp:hysteria  |  minapronetdev"
  echo " [Service]      : $STATUS"
  echo ""
  echo '=================================================='
  echo " BBR + 64MB UDP Buffers :  ACTIVE"
  echo " UDP Conntrack Timeout  :  300s (no drops)"
  echo " Auto-Restart Watchdog  :  ACTIVE (every 1 min)"
  echo " SSL Auto-Renew         :  ACTIVE"
  echo '=================================================='

  history -c
  rm -f /root/.installer /root/install_server.sh
  echo ""
  echo '[*] Rebooting in 20 seconds to apply all optimizations...'
  sleep 20
  reboot
}

# ============================================================
# RUN ALL
# ============================================================
install_require
optimize_kernel
install_hysteria
install_letsencrypt
install_firewall_kvm
modify_hysteria
install_squid
install_watchdog
install_rclocal
start_service
