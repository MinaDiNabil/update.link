#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  MinaProNet – Hysteria v1 Server  |  Ubuntu Installer
#  مبني على إعدادات UDPHysteriaThread.kt
#  يشمل: تثبيت ، سيرت TLS، systemd watchdog، BBR، UDP buffers، Health-check
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
#  ⚙️  الإعدادات – عدّلها حسب السيرفر
# ══════════════════════════════════════════════════════════════════════════════
HYSTERIA_PORT="5666"                        # البورت (من الكود: portHysteria)
HYSTERIA_OBFS="minapronet"                  # obfsHysteria
HYSTERIA_PASSWORD="mina:udp:hysteria"       # authHysteria
DOMAIN="udp-hysteria.minapronetvpn.com"     # اسم الدومين لـ TLS
TIMEZONE="Asia/Riyadh"

# نطاق السرعة للسيرفر (0 = غير محدود)
UP_MBPS=0
DOWN_MBPS=0

# مسارات الملفات
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_LOG="/var/log/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
CERT_FILE="${HYSTERIA_DIR}/server.crt"
KEY_FILE="${HYSTERIA_DIR}/server.key"
CA_FILE="${HYSTERIA_DIR}/ca.crt"

# إصدار Hysteria v1 (آخر إصدار مستقر)
HYSTERIA_VERSION="v1.3.5"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  HY_ARCH="amd64" ;;
  aarch64) HY_ARCH="arm64" ;;
  armv7l)  HY_ARCH="armv7" ;;
  *)       die "معمارية غير مدعومة: $ARCH" ;;
esac
HYSTERIA_URL="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/hysteria-linux-${HY_ARCH}"

# ══════════════════════════════════════════════════════════════════════════════
#  0. التحقق من الصلاحيات
# ══════════════════════════════════════════════════════════════════════════════
section "التحقق من المتطلبات"
[[ $EUID -eq 0 ]] || die "يجب تشغيل السكربت بصلاحيات root: sudo bash $0"
[[ -f /etc/os-release ]] && source /etc/os-release
info "النظام: ${PRETTY_NAME:-Ubuntu}"
info "المعمارية: $ARCH → $HY_ARCH"
info "البورت: $HYSTERIA_PORT | Obfs: $HYSTERIA_OBFS"
ok "الفحص اكتمل"

# ══════════════════════════════════════════════════════════════════════════════
#  1. تحديث النظام والحزم الأساسية
# ══════════════════════════════════════════════════════════════════════════════
section "تحديث النظام"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    curl wget openssl ufw cron logrotate \
    net-tools iproute2 ca-certificates gnupg lsb-release
timedatectl set-timezone "$TIMEZONE" 2>/dev/null || warn "فشل ضبط التوقيت"
ok "الحزم جاهزة"

# ══════════════════════════════════════════════════════════════════════════════
#  2. ضبط Kernel لأقصى أداء UDP
# ══════════════════════════════════════════════════════════════════════════════
section "ضبط Kernel (BBR + UDP Buffers)"

# BBR – خوارزمية ازدحام أفضل لـ QUIC/UDP
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf 2>/dev/null; then
cat >> /etc/sysctl.conf << 'SYSCTL'

# ── MinaProNet Hysteria Kernel Tuning ────────────────────────────────────────
# BBR congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# UDP socket buffers – مهم جداً لأداء QUIC
# recv_window في الكود = 491520 byte → نجعل الـ kernel يستوعب أكثر
net.core.rmem_max=134217728          # 128 MB – حد أقصى للاستقبال
net.core.wmem_max=134217728          # 128 MB – حد أقصى للإرسال
net.core.rmem_default=8388608        # 8 MB – افتراضي
net.core.wmem_default=8388608        # 8 MB – افتراضي
net.core.netdev_max_backlog=100000   # طابور الحزم

# IPv4 UDP
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192

# الاتصالات المتزامنة
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535

# إعادة استخدام المنافذ
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535

# تجنب fragmentation للـ UDP
net.ipv4.ip_no_pmtu_disc=0
net.ipv4.ip_forward=1
# ─────────────────────────────────────────────────────────────────────────────
SYSCTL
fi

sysctl -p > /dev/null 2>&1 || true

# التحقق من BBR
if lsmod | grep -q bbr 2>/dev/null || modprobe tcp_bbr 2>/dev/null; then
    ok "BBR مفعّل"
else
    warn "BBR غير متاح في هذا الكيرنل – سيستخدم الافتراضي"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  3. تحميل Hysteria v1
# ══════════════════════════════════════════════════════════════════════════════
section "تحميل Hysteria ${HYSTERIA_VERSION}"

NEEDS_DOWNLOAD=true
if [[ -f "$HYSTERIA_BIN" ]]; then
    CURRENT_VER=$("$HYSTERIA_BIN" version 2>/dev/null | grep -oP 'v\d+\.\d+\.\d+' | head -1 || echo "")
    if [[ "$CURRENT_VER" == "$HYSTERIA_VERSION" ]]; then
        ok "Hysteria ${HYSTERIA_VERSION} مثبّت بالفعل – تخطي التحميل"
        NEEDS_DOWNLOAD=false
    else
        info "إصدار موجود: ${CURRENT_VER:-غير معروف} → سيتم تحديثه"
    fi
fi

if $NEEDS_DOWNLOAD; then
    info "جاري التحميل من: $HYSTERIA_URL"
    TMP_BIN=$(mktemp)
    if ! curl -L --retry 5 --retry-delay 3 --connect-timeout 30 \
              -o "$TMP_BIN" "$HYSTERIA_URL"; then
        rm -f "$TMP_BIN"
        die "فشل تحميل Hysteria – تحقق من الاتصال"
    fi
    chmod +x "$TMP_BIN"
    # التحقق من الملف
    if ! "$TMP_BIN" version &>/dev/null; then
        rm -f "$TMP_BIN"
        die "الملف المحمّل تالف أو غير متوافق"
    fi
    # إيقاف الخدمة قبل استبدال الملف (إن وُجدت)
    systemctl stop hysteria 2>/dev/null || true
    mv "$TMP_BIN" "$HYSTERIA_BIN"
    ok "Hysteria $HYSTERIA_VERSION مثبّت في $HYSTERIA_BIN"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  4. إنشاء المجلدات والـ CA cert (نفس الكود الأصلي في UDPHysteriaThread.kt)
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد المجلدات والشهادات"
mkdir -p "$HYSTERIA_DIR" "$HYSTERIA_LOG"

# ── كتابة الـ CA cert الأصلي من الكود ─────────────────────────────────────
# هذا بالضبط نفس cert المضمّن في UDPHysteriaThread.kt
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
ok "CA cert كُتب من UDPHysteriaThread.kt"

# ── إنشاء شهادة TLS للسيرفر ─────────────────────────────────────────────────
# الكلاينت يستخدم insecure:true → أي شهادة تنفع
# لكن نجعلها مرتبطة بالدومين الصحيح لأقصى توافقية
if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
    info "إنشاء شهادة TLS self-signed لـ $DOMAIN …"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
        -nodes \
        -keyout "$KEY_FILE" \
        -out    "$CERT_FILE" \
        -subj   "/C=EG/O=MinaProNet/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN}" \
        2>/dev/null
    ok "شهادة TLS جاهزة (صالحة 10 سنوات)"
else
    ok "شهادة TLS موجودة – تخطي الإنشاء"
fi

chmod 600 "$KEY_FILE" "$CERT_FILE"

# ══════════════════════════════════════════════════════════════════════════════
#  5. كتابة config.json الخاص بالسيرفر
#     مطابق تماماً للـ recv_window في UDPHysteriaThread.kt (scaled ×170)
# ══════════════════════════════════════════════════════════════════════════════
section "كتابة إعدادات Hysteria Server"

# من الكود: rcCon=196608, rcW=(rcCon*5/2)=491520
# للسيرفر نستخدم القيم المحسّنة (32MB / 64MB) لأقصى استقرار
cat > "$HYSTERIA_CONFIG" << HYJSON
{
  "listen": ":${HYSTERIA_PORT}",
  "protocol": "udp",

  "obfs": "${HYSTERIA_OBFS}",

  "cert": "${CERT_FILE}",
  "key":  "${KEY_FILE}",

  "auth": {
    "mode": "password",
    "config": {
      "password": "${HYSTERIA_PASSWORD}"
    }
  },

  "up_mbps":   ${UP_MBPS},
  "down_mbps": ${DOWN_MBPS},

  "recv_window_conn":   33554432,
  "recv_window_client": 67108864,
  "max_conn_client":    4096,

  "disable_mtu_discovery": false,
  "resolve_preference":    "4",

  "log_level": "warn",
  "log_timestamp": true
}
HYJSON

chmod 600 "$HYSTERIA_CONFIG"
ok "config.json كُتب في $HYSTERIA_CONFIG"

# ══════════════════════════════════════════════════════════════════════════════
#  6. Systemd Service مع Watchdog + Auto-restart
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Systemd Service"

cat > /etc/systemd/system/hysteria.service << SERVICE
[Unit]
Description=MinaProNet Hysteria v1 VPN Server
Documentation=https://v1.hysteria.network/
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
ExecReload=/bin/kill -HUP \$MAINPID

# ── إعادة التشغيل التلقائي الفوري ────────────────────────────────────────────
Restart=always
RestartSec=1s
RestartForceExitStatus=0 1 2 255

# ── Watchdog – systemd يراقب العملية كل 30 ثانية ──────────────────────────────
WatchdogSec=30s
NotifyAccess=main

# ── الحد الأقصى للموارد ────────────────────────────────────────────────────────
LimitNOFILE=1048576
LimitNPROC=512
LimitCORE=infinity

# ── الأمان ────────────────────────────────────────────────────────────────────
ProtectSystem=strict
ReadWritePaths=${HYSTERIA_DIR} ${HYSTERIA_LOG}
PrivateTmp=true
NoNewPrivileges=true

# ── اللوق ─────────────────────────────────────────────────────────────────────
StandardOutput=append:${HYSTERIA_LOG}/hysteria.log
StandardError=append:${HYSTERIA_LOG}/hysteria-error.log
SyslogIdentifier=hysteria

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable hysteria
ok "Systemd service جاهز (auto-start عند الإقلاع)"

# ══════════════════════════════════════════════════════════════════════════════
#  7. Logrotate – تدوير اللوق تلقائياً
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Log Rotation"

cat > /etc/logrotate.d/hysteria << 'LOGROTATE'
/var/log/hysteria/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl kill -s HUP hysteria 2>/dev/null || true
    endscript
}
LOGROTATE
ok "Logrotate مضبوط (7 أيام)"

# ══════════════════════════════════════════════════════════════════════════════
#  8. Health-Check Cron كل دقيقة
#     لو مات السيرفر وsystemd فاته → الـ cron يُعيده
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد Health-Check Cron"

CRON_SCRIPT="/usr/local/bin/hysteria-healthcheck.sh"
cat > "$CRON_SCRIPT" << CRON
#!/bin/bash
# MinaProNet Hysteria Health-Check
LOG="${HYSTERIA_LOG}/healthcheck.log"
TS=\$(date '+%Y-%m-%d %H:%M:%S')

# تحقق إذا كانت العملية شغّالة
if ! systemctl is-active --quiet hysteria; then
    echo "[\$TS] WARN: hysteria down – restarting..." >> "\$LOG"
    systemctl restart hysteria
    sleep 3
    if systemctl is-active --quiet hysteria; then
        echo "[\$TS] OK: restarted successfully" >> "\$LOG"
    else
        echo "[\$TS] ERROR: restart failed!" >> "\$LOG"
    fi
fi

# تحقق إذا كان البورت يستجيب (UDP ping)
if ! ss -ulnp | grep -q ":${HYSTERIA_PORT}"; then
    echo "[\$TS] WARN: port ${HYSTERIA_PORT} not listening – forcing restart" >> "\$LOG"
    systemctl restart hysteria
fi
CRON

chmod +x "$CRON_SCRIPT"
# سجّل في crontab (كل دقيقة)
(crontab -l 2>/dev/null | grep -v "hysteria-healthcheck"; \
 echo "* * * * * /usr/local/bin/hysteria-healthcheck.sh") | crontab -
ok "Health-check cron كل دقيقة"

# ══════════════════════════════════════════════════════════════════════════════
#  9. الجدار الناري (UFW)
# ══════════════════════════════════════════════════════════════════════════════
section "إعداد الجدار الناري"

if command -v ufw &>/dev/null; then
    ufw allow ssh        comment "SSH" > /dev/null 2>&1 || true
    ufw allow "${HYSTERIA_PORT}/udp" comment "Hysteria VPN" > /dev/null 2>&1 || true
    ufw --force enable   > /dev/null 2>&1 || true
    ok "UFW: SSH + UDP/${HYSTERIA_PORT} مفتوحان"
else
    # iptables fallback
    iptables -I INPUT -p udp --dport "$HYSTERIA_PORT" -j ACCEPT 2>/dev/null || true
    warn "UFW غير موجود – تم فتح البورت عبر iptables مباشرة"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  10. تشغيل الخدمة
# ══════════════════════════════════════════════════════════════════════════════
section "تشغيل Hysteria Server"

systemctl restart hysteria
sleep 3

if systemctl is-active --quiet hysteria; then
    ok "✅ Hysteria يعمل بنجاح!"
else
    warn "الخدمة لم تبدأ – تفقد اللوق:"
    journalctl -u hysteria -n 30 --no-pager
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
#  ملخص نهائي
# ══════════════════════════════════════════════════════════════════════════════
PUBIP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "تعذّر جلب IP")

echo ""
echo -e "${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          ✅  MinaProNet Hysteria v1 – جاهز للعمل            ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
printf  "║  🌐 IP السيرفر    : %-40s ║\n" "$PUBIP"
printf  "║  🔒 الدومين       : %-40s ║\n" "$DOMAIN"
printf  "║  🔌 البورت        : %-40s ║\n" "${HYSTERIA_PORT}/UDP"
printf  "║  🔑 كلمة السر     : %-40s ║\n" "$HYSTERIA_PASSWORD"
printf  "║  🌀 Obfs          : %-40s ║\n" "$HYSTERIA_OBFS"
printf  "║  📦 الإصدار       : %-40s ║\n" "$HYSTERIA_VERSION"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  الأوامر المفيدة:                                            ║"
echo "║  systemctl status hysteria         # حالة السيرفر           ║"
echo "║  systemctl restart hysteria        # إعادة التشغيل          ║"
echo "║  tail -f /var/log/hysteria/*.log   # متابعة اللوق           ║"
echo "║  ss -ulnp | grep ${HYSTERIA_PORT}              # فحص البورت         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}⚠️  تنبيه: غيّر HYSTERIA_PASSWORD في أعلى السكربت قبل الإنتاج!${NC}"
echo ""
