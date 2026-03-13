#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  MinaProNet – Hysteria v1 Server  |  Ubuntu Installer  v3.0
#  ✅ Port Hopping  1–65535  →  يعمل على جميع البورتات
#  ✅ لا انقطاع    – QUIC tuned + BBR + systemd watchdog + healthcheck
#  ✅ سرعة عالية   – UDP buffers 128MB + window 64MB
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── الألوان ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ══════════════════════════════════════════════════════════════════════════════
#  ⚙️  الإعدادات
# ══════════════════════════════════════════════════════════════════════════════
HYSTERIA_PORT="5666"
PORT_HOP_START="1"
PORT_HOP_END="65535"
HYSTERIA_OBFS="minapronet"
HYSTERIA_PASSWORD="mina:udp:hysteria"
DOMAIN="udp-hysteria.minapronetvpn.com"
TIMEZONE="Asia/Riyadh"

HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_LOG="/var/log/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
CERT_FILE="${HYSTERIA_DIR}/server.crt"
KEY_FILE="${HYSTERIA_DIR}/server.key"
CA_FILE="${HYSTERIA_DIR}/ca.crt"
IPTABLES_SCRIPT="/etc/hysteria/port-hopping.sh"

HYSTERIA_VERSION="v1.3.5"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  HY_ARCH="amd64" ;;
  aarch64) HY_ARCH="arm64" ;;
  armv7l)  HY_ARCH="armv7" ;;
  *)       die "معمارية غير مدعومة: $ARCH" ;;
esac
HYSTERIA_URL_PRIMARY="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/hysteria-linux-${HY_ARCH}"
HYSTERIA_URL_FALLBACK="https://download.fastgit.org/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/hysteria-linux-${HY_ARCH}"

# ══════════════════════════════════════════════════════════════════════════════
#  0. التحقق من الصلاحيات
# ══════════════════════════════════════════════════════════════════════════════
section "التحقق من المتطلبات"
[[ $EUID -eq 0 ]] || die "يجب تشغيل السكربت بصلاحيات root"
[[ -f /etc/os-release ]] && source /etc/os-release
info "النظام: ${PRETTY_NAME:-Ubuntu}"
info "المعمارية: $ARCH → $HY_ARCH"
info "البورت: $HYSTERIA_PORT | Obfs: $HYSTERIA_OBFS"
info "Port Hopping: UDP ${PORT_HOP_START}–${PORT_HOP_END} → ${HYSTERIA_PORT}"
ok "الفحص اكتمل"

# ══════════════════════════════════════════════════════════════════════════════
#  1. تحديث النظام والحزم
# ══════════════════════════════════════════════════════════════════════════════
section "تحديث النظام"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    curl wget openssl cron logrotate file \
    net-tools iproute2 ca-certificates \
    iptables iptables-persistent netfilter-persistent
timedatectl set-timezone "$TIMEZONE" 2>/dev/null || true
ok "الحزم جاهزة"

# ══════════════════════════════════════════════════════════════════════════════
#  2. ضبط Kernel
# ══════════════════════════════════════════════════════════════════════════════
section "ضبط Kernel (BBR + UDP Buffers)"

sed -i '/# MinaProNet Hysteria/,/^# ───/d' /etc/sysctl.conf 2>/dev/null || true

cat >> /etc/sysctl.conf << 'SYSCTL'

# MinaProNet Hysteria Kernel Tuning ──────────────────────────────────────────
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=8388608
net.core.wmem_default=8388608
net.core.netdev_max_backlog=250000
net.core.optmem_max=67108864
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_forward=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
# ────────────────────────────────────────────────────────────────────────────
SYSCTL

sysctl -p > /dev/null 2>&1 || true
modprobe tcp_bbr 2>/dev/null || true

if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    ok "BBR مفعّل ✅"
else
    warn "BBR غير متاح في هذا الكيرنل"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  3. Port Hopping – iptables DNAT
#     الجوهر: كل UDP وارد على أي بورت يُحوَّل تلقائياً لـ 5666
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Port Hopping (UDP ${PORT_HOP_START}-${PORT_HOP_END} → ${HYSTERIA_PORT})"

MAIN_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
[[ -z "$MAIN_IFACE" ]] && MAIN_IFACE="eth0"
info "الواجهة الشبكية: $MAIN_IFACE"

mkdir -p "$HYSTERIA_DIR"

cat > "$IPTABLES_SCRIPT" << IPHOP
#!/bin/bash
IFACE="${MAIN_IFACE}"
MAIN_PORT="${HYSTERIA_PORT}"
HOP_START="${PORT_HOP_START}"
HOP_END="${PORT_HOP_END}"

apply_rules() {
    # امسح القديم أولاً
    while iptables -t nat -D PREROUTING -i \$IFACE -p udp \
        --dport \${HOP_START}:\${HOP_END} -j REDIRECT --to-ports \$MAIN_PORT 2>/dev/null; do :; done

    # أضف DNAT rule
    iptables -t nat -A PREROUTING -i \$IFACE -p udp \
        --dport \${HOP_START}:\${HOP_END} \
        -j REDIRECT --to-ports \$MAIN_PORT

    echo "[OK] Port Hopping: UDP \${HOP_START}-\${HOP_END} → \${MAIN_PORT}"
}

remove_rules() {
    while iptables -t nat -D PREROUTING -i \$IFACE -p udp \
        --dport \${HOP_START}:\${HOP_END} -j REDIRECT --to-ports \$MAIN_PORT 2>/dev/null; do :; done
    echo "[OK] Port Hopping rules removed"
}

case "\${1:-apply}" in
    apply)  apply_rules ;;
    remove) remove_rules ;;
esac
IPHOP

chmod +x "$IPTABLES_SCRIPT"
bash "$IPTABLES_SCRIPT" apply

# احفظ لما بعد reboot
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

# rc.local كضمان ثانوي
if [[ ! -f /etc/rc.local ]]; then
    printf '#!/bin/bash\nexit 0\n' > /etc/rc.local
    chmod +x /etc/rc.local
fi
grep -q "port-hopping" /etc/rc.local || \
    sed -i "s|^exit 0|bash ${IPTABLES_SCRIPT} apply\nexit 0|" /etc/rc.local

ok "Port Hopping مفعّل: UDP 1–65535 → $HYSTERIA_PORT"

# ══════════════════════════════════════════════════════════════════════════════
#  4. تحميل Hysteria v1
# ══════════════════════════════════════════════════════════════════════════════
section "تحميل Hysteria ${HYSTERIA_VERSION}"

TMP_BIN=$(mktemp)
info "جاري التحميل …"
DOWNLOAD_OK=false

if curl -L --retry 3 --retry-delay 2 --connect-timeout 30 \
        --progress-bar -o "$TMP_BIN" "$HYSTERIA_URL_PRIMARY" 2>/dev/null; then
    DOWNLOAD_OK=true
else
    warn "المصدر الأساسي فشل – تجربة البديل …"
    curl -L --retry 3 --retry-delay 2 --connect-timeout 30 \
         --progress-bar -o "$TMP_BIN" "$HYSTERIA_URL_FALLBACK" \
         && DOWNLOAD_OK=true || true
fi

$DOWNLOAD_OK || { rm -f "$TMP_BIN"; die "فشل التحميل من جميع المصادر"; }

chmod +x "$TMP_BIN"

FILE_SIZE=$(stat -c%s "$TMP_BIN" 2>/dev/null || echo 0)
if [[ "$FILE_SIZE" -lt 1048576 ]]; then
    rm -f "$TMP_BIN"
    die "الملف صغير جداً (${FILE_SIZE} bytes) – رابط خاطئ أو ملف تالف"
fi
if ! file "$TMP_BIN" 2>/dev/null | grep -q "ELF"; then
    rm -f "$TMP_BIN"
    die "الملف ليس ELF binary صالح"
fi

systemctl stop hysteria 2>/dev/null || true
mv "$TMP_BIN" "$HYSTERIA_BIN"
ok "Hysteria $HYSTERIA_VERSION مثبّت"

# ══════════════════════════════════════════════════════════════════════════════
#  5. الشهادات
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد الشهادات"
mkdir -p "$HYSTERIA_DIR" "$HYSTERIA_LOG"

cat > "$CA_FILE" << 'CACERT'
-----BEGIN CERTIFICATE-----
MIIDizCCAnOgAwIBAgIUGxLl5Ou4dR1h3c9lUcaM5bp4ZBswDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkdEMQswCQYDVQQHDAJTWjEUMBIG
A1UECgwLWklWUE4sIEluYy4xFjAUBgNVBAMMDVpJVlBOIFJvb3QgQ0EwHhcNMjMw
MjExMDkwMjM1WhcNMzMwMjA4MDkwMjM1WjBVMQswCQYDVQQGEwJDTjELMAkGA1UE
CAwCR0QxCzAJBgNVBAcMAlNaMRQwEgYDVQQKDAtaSVZQTiwgSW5jLjEWMBQGA1UE
AwwNWklWUE4gUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMQsHTq2UD4WDOvNUFGQuKd0PEitgQzSh12qH9aJ5jnCtbWjqVNDRQSW0ietg4Po
qOfKLOBvGOJcGkrYlAAynnwsufdkZd2Jj2+FAXloAbMBK5cjqRANfPJ7ns3S5zL2
t2+Xv/O6H58NL5QksyIHb2Vcosfelwuvj5Lq+MvyqGZikce5IaykgjjV0OsrBnsC
eK4yAeoxsqVixGwmcJDLGOIJDGYcDdaElqJqFCyOjOhLLDymx9JbeOb3DpiRNFNN
lwXi2rfvpnmpGNwNt9sclWAQTL3cfV4GsCovT02r1qxcAqqRE4U1nqMRqk0KfyQn
UebOat/0jNJI9YxJByuVBK0CAwEAAaNTMFEwHQYDVR0OBBYEFGk91bjhFZfcKkpm
5SxVkqnSGhXBMB8GA1UdIwQYMBaAFGk91bjhFZfcKkpm5SxVkqnSGhXBMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEr4aeE0ib5/7neEcRWCE1pg
w0j/958bdaSdQJJvYEpc7brCHhp5lmNJA+MjVcCXCL4/8KfuEcyGNPPSPo7wbuYJ
O9jsJmQOklfyvlKGJschvc8AZ0E0AGdrgGam1KApjrb6Xly5bqgV4KPBQ7KttBVw
wFfTm0yjD3nAjaSXi3I/MG+gMGnUXoTMZa3iS2pomBMHLdTksiujbbH7RP9mzPT3
7UvyVmtw7eQFEjEYceVWHlhXCjL9gpcJiX/wu9XzREDpNCqY2R3zb+ZGYuQD0L5h
zv0u1CF+Cfkkg8luxol+aWc+1ac/8TGLV1WOGj4FuEMfxQPXWFqhc8VEyxZ/r/w=
-----END CERTIFICATE-----
CACERT

if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
    info "إنشاء شهادة TLS …"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=EG/O=MinaProNet/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null
    ok "شهادة TLS جاهزة"
else
    ok "شهادة TLS موجودة"
fi
chmod 600 "$KEY_FILE" "$CERT_FILE"

# ══════════════════════════════════════════════════════════════════════════════
#  6. config.json
# ══════════════════════════════════════════════════════════════════════════════
section "كتابة config.json"

cat > "$HYSTERIA_CONFIG" << HYJSON
{
  "listen": ":${HYSTERIA_PORT}",
  "cert": "${CERT_FILE}",
  "key":  "${KEY_FILE}",
  "obfs": "${HYSTERIA_OBFS}",
  "auth": {
    "mode": "password",
    "config": {
      "password": "${HYSTERIA_PASSWORD}"
    }
  },
  "up_mbps":            100,
  "down_mbps":          100,
  "recv_window_conn":   33554432,
  "recv_window_client": 67108864,
  "max_conn_client":    0,
  "disable_mtu_discovery": false,
  "resolve_preference": "4",
  "alpn":               "h3",
  "log_level":          "warn"
}
HYJSON

chmod 600 "$HYSTERIA_CONFIG"
ok "config.json كُتب"

# ══════════════════════════════════════════════════════════════════════════════
#  7. Systemd Service
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Systemd"

cat > /etc/systemd/system/hysteria.service << SERVICE
[Unit]
Description=MinaProNet Hysteria v1 VPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStartPre=/bin/bash ${IPTABLES_SCRIPT} apply
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
ExecReload=/bin/kill -HUP \$MAINPID
ExecStopPost=/bin/bash ${IPTABLES_SCRIPT} apply

Restart=always
RestartSec=1s
WatchdogSec=60s

LimitNOFILE=1048576
LimitNPROC=unlimited

StandardOutput=append:${HYSTERIA_LOG}/hysteria.log
StandardError=append:${HYSTERIA_LOG}/hysteria-error.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable hysteria
ok "Systemd service مضبوط (Restart=always)"

# ══════════════════════════════════════════════════════════════════════════════
#  8. Health-Check Cron
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Health-Check"

cat > /usr/local/bin/hysteria-check.sh << HEALTHCHECK
#!/bin/bash
LOG="${HYSTERIA_LOG}/healthcheck.log"
TS=\$(date '+%Y-%m-%d %H:%M:%S')

if ! systemctl is-active --quiet hysteria; then
    echo "[\$TS] hysteria down – restarting" >> "\$LOG"
    systemctl restart hysteria
    sleep 2
fi

if ! ss -ulnp 2>/dev/null | grep -q ":${HYSTERIA_PORT}"; then
    echo "[\$TS] port ${HYSTERIA_PORT} not listening – restart" >> "\$LOG"
    systemctl restart hysteria
fi

if ! iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports ${HYSTERIA_PORT}"; then
    echo "[\$TS] port-hopping lost – reapplying" >> "\$LOG"
    bash ${IPTABLES_SCRIPT} apply
fi
HEALTHCHECK

chmod +x /usr/local/bin/hysteria-check.sh
(crontab -l 2>/dev/null | grep -v "hysteria-check"; \
 echo "* * * * * /usr/local/bin/hysteria-check.sh") | crontab -
ok "Health-check كل دقيقة (خدمة + بورت + Port Hopping)"

# Logrotate
cat > /etc/logrotate.d/hysteria << 'LOGROTATE'
/var/log/hysteria/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
LOGROTATE

# ══════════════════════════════════════════════════════════════════════════════
#  9. الجدار الناري – أوقف UFW (يعطّل DNAT)
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد الجدار الناري"

if systemctl is-active --quiet ufw 2>/dev/null; then
    ufw disable > /dev/null 2>&1 || true
    info "تم إيقاف UFW (يتعارض مع Port Hopping DNAT)"
fi

iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p udp --dport "$HYSTERIA_PORT" -j ACCEPT 2>/dev/null || true
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true
ok "iptables محفوظ (SSH + UDP $HYSTERIA_PORT + DNAT)"

# ══════════════════════════════════════════════════════════════════════════════
#  10. تشغيل الخدمة
# ══════════════════════════════════════════════════════════════════════════════
section "تشغيل Hysteria"
systemctl restart hysteria
sleep 4

if systemctl is-active --quiet hysteria; then
    ok "✅ Hysteria يعمل"
else
    warn "الخدمة لم تبدأ – اللوق:"
    journalctl -u hysteria -n 40 --no-pager
    exit 1
fi

if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports $HYSTERIA_PORT"; then
    ok "✅ Port Hopping يعمل"
else
    warn "Port Hopping قد لا يعمل – راجع iptables"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  الملخص
# ══════════════════════════════════════════════════════════════════════════════
PUBIP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "N/A")

echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║       ✅  MinaProNet Hysteria v1 – جاهز للعمل                  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
printf  "║  🌐 IP السيرفر      : %-41s║\n" "$PUBIP"
printf  "║  🔒 الدومين         : %-41s║\n" "$DOMAIN"
printf  "║  🔌 البورت الرئيسي  : %-41s║\n" "${HYSTERIA_PORT}/UDP"
printf  "║  🔀 Port Hopping    : %-41s║\n" "UDP 1–65535 → ${HYSTERIA_PORT}"
printf  "║  🔑 كلمة السر       : %-41s║\n" "$HYSTERIA_PASSWORD"
printf  "║  🌀 Obfs            : %-41s║\n" "$HYSTERIA_OBFS"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  في التطبيق: اكتب أي بورت من 1 إلى 65535 وسيعمل             ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  أوامر مفيدة:                                                  ║"
echo "║  systemctl status hysteria                                     ║"
echo "║  iptables -t nat -L PREROUTING -n -v  # فحص Port Hopping      ║"
echo "║  tail -f /var/log/hysteria/hysteria.log                        ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
