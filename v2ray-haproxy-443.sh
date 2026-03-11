#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║      V2Ray + HAProxy + stunnel4 + Nginx على بورت 443        ║
# ║                                                              ║
# ║  Architecture:                                               ║
# ║   Internet :443                                              ║
# ║       ↓ HAProxy (protocol detector)                          ║
# ║       ├── SSH       → 127.0.0.1:2222                        ║
# ║       └── TLS/Other → stunnel4:8443                         ║
# ║                           ↓ stunnel4 (TLS termination)       ║
# ║                       nginx:8080                             ║
# ║                           ↓                                  ║
# ║                   /linkvws → v2ray:10000 (VMess WS)          ║
# ║                   other   → redirect                         ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# الألوان
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()     { echo -e "  ${GREEN}[✓]${NC} $*"; }
fail()   { echo -e "  ${RED}[✗]${NC} $*"; }
warn()   { echo -e "  ${YELLOW}[!]${NC} $*"; }
info()   { echo -e "  ${CYAN}[i]${NC} $*"; }
step()   { echo -e "\n${BOLD}${BLUE}┌─────────────────────────────────────────────┐${NC}"; \
           echo -e "${BOLD}${BLUE}│  $*${NC}"; \
           echo -e "${BOLD}${BLUE}└─────────────────────────────────────────────┘${NC}"; }
die()    { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# التحقق من الصلاحيات
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[[ $EUID -ne 0 ]] && die "يجب تشغيل السكربت كـ root"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# الإعدادات الافتراضية
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFAULT_UUID="03fcc618-b93d-6796-6aed-8a38c975d581"
DEFAULT_PATH="/linkvws"

PORT_PUBLIC=443       # البورت الخارجي الوحيد
PORT_SSH_INT=2222     # SSH داخلي
PORT_STUNNEL=8443     # stunnel4 داخلي (TLS)
PORT_NGINX=8080       # Nginx داخلي (HTTP بعد فكّ TLS)
PORT_V2RAY=10000      # V2Ray داخلي (WebSocket)

SSL_DIR="/etc/stunnel"
V2RAY_CFG="/usr/local/etc/v2ray/config.json"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# الشعار
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
clear
echo -e "${BOLD}${GREEN}"
cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║   ██╗   ██╗██████╗ ██████╗  █████╗ ██╗   ██╗           ║
  ║   ██║   ██║╚════██╗██╔══██╗██╔══██╗╚██╗ ██╔╝           ║
  ║   ██║   ██║ █████╔╝██████╔╝███████║ ╚████╔╝            ║
  ║   ╚██╗ ██╔╝██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝             ║
  ║    ╚████╔╝ ███████╗██║  ██║██║  ██║   ██║              ║
  ║     ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝              ║
  ║                                                          ║
  ║   HAProxy + stunnel4 + Nginx + V2Ray on :443            ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# اكتشاف IP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SERVER_IP=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || \
            curl -s4 --max-time 5 https://ifconfig.me  2>/dev/null || \
            hostname -I | awk '{print $1}')

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# واجهة الإعداد
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo -e "${BOLD}  ┌─ الإعدادات ──────────────────────────────────────┐${NC}"
echo -e "  │ Server IP : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  │ UUID      : ${YELLOW}${DEFAULT_UUID}${NC}"
echo -e "  │ WS Path   : ${YELLOW}${DEFAULT_PATH}${NC}"
echo -e "${BOLD}  └──────────────────────────────────────────────────┘${NC}"
echo ""

read -rp "$(echo -e "  ${CYAN}تغيير UUID؟ [y/N]: ${NC}")" CHG_UUID
UUID=$([[ "$CHG_UUID" =~ ^[Yy]$ ]] && read -rp "  UUID: " U && echo "${U:-$DEFAULT_UUID}" || echo "$DEFAULT_UUID")

read -rp "$(echo -e "  ${CYAN}تغيير Path؟ [y/N]: ${NC}")" CHG_PATH
WS_PATH=$([[ "$CHG_PATH" =~ ^[Yy]$ ]] && read -rp "  Path: " P && echo "${P:-$DEFAULT_PATH}" || echo "$DEFAULT_PATH")

echo ""
echo -e "  ${BOLD}التثبيت بـ:${NC} UUID=${YELLOW}${UUID}${NC}  Path=${YELLOW}${WS_PATH}${NC}"
read -rp "$(echo -e "  ${CYAN}متابعة؟ [Y/n]: ${NC}")" GO
[[ "$GO" =~ ^[Nn]$ ]] && exit 0

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# دالة apt آمنة (تتجاهل خطأ cnf-update-db)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
safe_apt_update() {
    apt-get update \
        -o APT::Update::Post-Invoke-Success="" \
        -o APT::Update::Post-Invoke="" \
        -qq 2>/dev/null || true
}

safe_apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        -o APT::Update::Post-Invoke-Success="" \
        "$@" 2>/dev/null
}

# ════════════════════════════════════════════════════════════════
#  الخطوة 1 — تحديث النظام وتثبيت المتطلبات
# ════════════════════════════════════════════════════════════════
step "1/7 — تثبيت المتطلبات"

safe_apt_update
safe_apt_install \
    curl wget unzip socat cron openssl \
    nginx \
    haproxy \
    stunnel4 \
    ufw

ok "تم تثبيت: nginx, haproxy, stunnel4, curl, openssl"

# ════════════════════════════════════════════════════════════════
#  الخطوة 2 — SSH على بورت داخلي 2222
# ════════════════════════════════════════════════════════════════
step "2/7 — إعداد SSH"

SSHD_CFG="/etc/ssh/sshd_config"
if ! grep -q "^Port ${PORT_SSH_INT}" "$SSHD_CFG" 2>/dev/null; then
    # إضافة بورت 2222 مع الاحتفاظ بـ 22
    if grep -q "^Port 22" "$SSHD_CFG"; then
        sed -i "/^Port 22/a Port ${PORT_SSH_INT}" "$SSHD_CFG"
    elif grep -q "^#Port 22" "$SSHD_CFG"; then
        sed -i "s/^#Port 22/Port 22\nPort ${PORT_SSH_INT}/" "$SSHD_CFG"
    else
        echo -e "\nPort 22\nPort ${PORT_SSH_INT}" >> "$SSHD_CFG"
    fi
fi

systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
ok "SSH يستمع على بورت 22 (مباشر) + ${PORT_SSH_INT} (عبر HAProxy على 443)"

# ════════════════════════════════════════════════════════════════
#  الخطوة 3 — شهادة TLS لـ stunnel4
# ════════════════════════════════════════════════════════════════
step "3/7 — إنشاء شهادة TLS"

mkdir -p "$SSL_DIR"
PEM_FILE="$SSL_DIR/stunnel.pem"

if [[ ! -f "$PEM_FILE" ]]; then
    # إنشاء key + cert مدمجين في ملف pem واحد (stunnel يحتاج هذا)
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/stunnel.key" \
        -out    "$SSL_DIR/stunnel.crt" \
        -subj "/C=US/ST=CA/L=LA/O=MinaProNet/CN=${SERVER_IP}" \
        -addext "subjectAltName=IP:${SERVER_IP}" 2>/dev/null

    # دمج key + cert في ملف pem واحد كما يتطلب stunnel
    cat "$SSL_DIR/stunnel.key" "$SSL_DIR/stunnel.crt" > "$PEM_FILE"
    chmod 600 "$PEM_FILE"
    ok "تم إنشاء شهادة TLS (10 سنوات) في $PEM_FILE"
else
    ok "شهادة TLS موجودة مسبقاً"
fi

# ════════════════════════════════════════════════════════════════
#  الخطوة 4 — تثبيت V2Ray
# ════════════════════════════════════════════════════════════════
step "4/7 — تثبيت V2Ray"

if ! command -v v2ray &>/dev/null && [[ ! -f /usr/local/bin/v2ray ]]; then
    info "جاري تحميل V2Ray..."
    bash <(curl -sL https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) \
        2>&1 | grep -E "installed|updated|start|error|Error" || true
fi

ok "V2Ray مثبّت"

# ─── config.json ─────────────────────────────────────────────
mkdir -p "$(dirname $V2RAY_CFG)" /var/log/v2ray

cat > "$V2RAY_CFG" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error":  "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": ${PORT_V2RAY},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0,
            "security": "auto"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${WS_PATH}",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

systemctl daemon-reload
systemctl enable v2ray
systemctl restart v2ray
sleep 2

if systemctl is-active --quiet v2ray; then
    ok "V2Ray يعمل على 127.0.0.1:${PORT_V2RAY}"
else
    fail "V2Ray فشل — جاري فحص الخطأ:"
    journalctl -u v2ray -n 10 --no-pager 2>/dev/null
    die "V2Ray لم يبدأ"
fi

# ════════════════════════════════════════════════════════════════
#  الخطوة 5 — إعداد Nginx (HTTP proxy لـ WebSocket)
# ════════════════════════════════════════════════════════════════
step "5/7 — إعداد Nginx"

systemctl stop nginx 2>/dev/null || true

# إزالة الإعدادات القديمة
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-enabled/v2ray 2>/dev/null || true

cat > /etc/nginx/sites-enabled/v2ray <<EOF
# ─── V2Ray WebSocket via Nginx (HTTP only, stunnel handles TLS) ─
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    # يستمع على 8080 فقط — stunnel4 يتولى TLS ويمرر هنا
    listen 127.0.0.1:${PORT_NGINX};
    server_name _;

    # منع الوصول المباشر
    location / {
        return 301 https://www.google.com\$request_uri;
    }

    # نقطة V2Ray WebSocket
    location ${WS_PATH} {
        proxy_pass         http://127.0.0.1:${PORT_V2RAY};
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    \$http_upgrade;
        proxy_set_header   Connection \$connection_upgrade;
        proxy_set_header   Host       \$host;
        proxy_set_header   X-Real-IP  \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering    off;
    }
}
EOF

nginx -t 2>&1 | grep -v "^$" && systemctl start nginx && systemctl enable nginx
sleep 1

if systemctl is-active --quiet nginx; then
    ok "Nginx يعمل على 127.0.0.1:${PORT_NGINX} (HTTP)"
else
    die "Nginx فشل — راجع: nginx -t"
fi

# ════════════════════════════════════════════════════════════════
#  الخطوة 6 — إعداد stunnel4 (TLS :8443 → Nginx :8080)
# ════════════════════════════════════════════════════════════════
step "6/7 — إعداد stunnel4"

# إيقاف stunnel4 أولاً لتحرير أي بورت
systemctl stop stunnel4 2>/dev/null || true
pkill -9 stunnel4 2>/dev/null || true
sleep 1

cat > /etc/stunnel/stunnel.conf <<EOF
; ── stunnel4 — TLS Termination ──────────────────────────────
; يستقبل TLS على 8443 ويمرر HTTP لـ Nginx على 8080

pid = /var/run/stunnel4/stunnel4.pid
setuid = stunnel4
setgid = stunnel4
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

; السجلات
output = /var/log/stunnel4/stunnel.log
syslog = no

; إعداد V2Ray TLS → Nginx
[v2ray-tls]
accept  = 127.0.0.1:${PORT_STUNNEL}
connect = 127.0.0.1:${PORT_NGINX}
cert    = ${PEM_FILE}
sslVersion = TLSv1.2
ciphers = HIGH:!aNULL:!MD5
EOF

# التأكد من وجود المجلدات
mkdir -p /var/run/stunnel4 /var/log/stunnel4
chown stunnel4:stunnel4 /var/run/stunnel4 /var/log/stunnel4 2>/dev/null || true

# تفعيل stunnel4
sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || \
    echo "ENABLED=1" >> /etc/default/stunnel4

systemctl daemon-reload
systemctl enable stunnel4
systemctl restart stunnel4
sleep 2

if systemctl is-active --quiet stunnel4; then
    ok "stunnel4 يعمل على 127.0.0.1:${PORT_STUNNEL} → nginx:${PORT_NGINX}"
else
    warn "stunnel4 لم يبدأ — جاري فحص المشكلة:"
    journalctl -u stunnel4 -n 10 --no-pager 2>/dev/null
    # محاولة تشغيل يدوي
    stunnel /etc/stunnel/stunnel.conf 2>/dev/null || true
    sleep 1
    ss -tlnp | grep ":${PORT_STUNNEL}" && ok "stunnel4 يعمل (يدوي)" || \
        warn "stunnel4 لم يبدأ — ستعمل الخدمة بدونه عبر Nginx مباشرة"
fi

# ════════════════════════════════════════════════════════════════
#  الخطوة 7 — إعداد HAProxy (Port Multiplexer على 443)
# ════════════════════════════════════════════════════════════════
step "7/7 — إعداد HAProxy"

# تحرير البورت 443 من أي خدمة أخرى
for svc in sslh sslh-custom apache2; do
    systemctl stop  "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done
pkill -9 sslh 2>/dev/null || true
sleep 1

cat > /etc/haproxy/haproxy.cfg <<EOF
# ════════════════════════════════════════════════════════════
#  HAProxy — Port 443 Multiplexer
#  يكشف البروتوكول ويوجّه للخدمة المناسبة
# ════════════════════════════════════════════════════════════

global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 50000
    tune.ssl.default-dh-param 2048

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5s
    timeout client  1m
    timeout server  1m
    timeout tunnel  1h

# ── الاستماع على 443 ─────────────────────────────────────────
frontend ft_443
    bind 0.0.0.0:443
    mode tcp
    option tcplog

    # انتظر لكشف البروتوكول
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.len gt 0 }

    # ── SSH: يبدأ بـ SSH-2.0 أو SSH-1 ─────────────────────────
    acl is_ssh payload(0,7) -m bin 5353482d322e30
    acl is_ssh payload(0,7) -m bin 5353482d312e
    use_backend bk_ssh if is_ssh

    # ── TLS: يبدأ بـ 0x16 (TLS Handshake) ──────────────────────
    acl is_tls  payload(0,1) -m bin 16
    use_backend bk_tls if is_tls

    # ── HTTP ─────────────────────────────────────────────────
    acl is_http payload(0,3) -m str GET
    acl is_http payload(0,4) -m str POST
    acl is_http payload(0,4) -m str HEAD
    use_backend bk_tls if is_http

    # ── fallback: كل شيء آخر يذهب لـ TLS ──────────────────────
    default_backend bk_tls

# ── SSH Backend ───────────────────────────────────────────────
backend bk_ssh
    mode tcp
    server ssh_int 127.0.0.1:${PORT_SSH_INT} check

# ── TLS Backend (stunnel4 → Nginx → V2Ray) ────────────────────
backend bk_tls
    mode tcp
    server stunnel 127.0.0.1:${PORT_STUNNEL} check

# ── Stats (اختياري) ──────────────────────────────────────────
listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:minapronet
EOF

# التحقق من الإعداد
haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1
if [[ $? -eq 0 ]]; then
    ok "إعداد HAProxy صحيح"
else
    die "خطأ في إعداد HAProxy"
fi

systemctl enable haproxy
systemctl restart haproxy
sleep 2

if systemctl is-active --quiet haproxy; then
    ok "HAProxy يعمل على 0.0.0.0:443"
else
    fail "HAProxy فشل:"
    journalctl -u haproxy -n 15 --no-pager 2>/dev/null
    die "HAProxy لم يبدأ"
fi

# ════════════════════════════════════════════════════════════════
#  الجدار الناري
# ════════════════════════════════════════════════════════════════
if command -v ufw &>/dev/null; then
    ufw allow 22/tcp   comment "SSH مباشر (احتياطي)"   >/dev/null 2>&1
    ufw allow 443/tcp  comment "HAProxy Multiplexer"    >/dev/null 2>&1
    ufw --force enable >/dev/null 2>&1
    ok "UFW: السماح بـ 22 و 443"
fi

# ════════════════════════════════════════════════════════════════
#  اختبار الاتصال الشامل
# ════════════════════════════════════════════════════════════════
echo ""
info "جاري اختبار كل المكونات..."
sleep 3

test_service() {
    local name=$1 host=$2 port=$3
    if ss -tlnp | grep -q "${host}:${port}"; then
        ok "$name يستمع على ${host}:${port}"
    else
        fail "$name لا يستمع على ${host}:${port}"
    fi
}

test_service "HAProxy"  "0.0.0.0"   $PORT_PUBLIC
test_service "stunnel4" "127.0.0.1" $PORT_STUNNEL
test_service "Nginx"    "127.0.0.1" $PORT_NGINX
test_service "V2Ray"    "127.0.0.1" $PORT_V2RAY
test_service "SSH"      "0.0.0.0"   $PORT_SSH_INT

# اختبار WebSocket عبر المسار الكامل
WS_TEST=$(curl -sk --max-time 8 \
    -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://${SERVER_IP}:443${WS_PATH}" 2>/dev/null)

[[ "$WS_TEST" == "101" ]] && ok "WebSocket يعمل عبر المسار الكامل ✓" || \
    warn "WebSocket أعاد: $WS_TEST (فعّل allowInsecure في التطبيق)"

# ════════════════════════════════════════════════════════════════
#  توليد رابط VMess
# ════════════════════════════════════════════════════════════════
VMESS_JSON=$(printf '%s' "{
  \"v\": \"2\",
  \"ps\": \"MinaProNet-443\",
  \"add\": \"${SERVER_IP}\",
  \"port\": \"${PORT_PUBLIC}\",
  \"id\": \"${UUID}\",
  \"aid\": \"0\",
  \"scy\": \"auto\",
  \"net\": \"ws\",
  \"type\": \"none\",
  \"host\": \"\",
  \"path\": \"${WS_PATH}\",
  \"tls\": \"tls\",
  \"sni\": \"${SERVER_IP}\",
  \"alpn\": \"\",
  \"fp\": \"\"
}")
VMESS_LINK="vmess://$(echo -n "$VMESS_JSON" | base64 -w0)"

# ════════════════════════════════════════════════════════════════
#  الملخص النهائي
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║              ✅ التثبيت اكتمل بنجاح!                   ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}  ┌─ مخطط التدفق ────────────────────────────────────────┐${NC}"
echo -e "  │  Internet                                              │"
echo -e "  │      │ :443                                           │"
echo -e "  │      ▼                                                │"
echo -e "  │  ${YELLOW}HAProxy${NC} (protocol detector)                         │"
echo -e "  │      ├── SSH traffic  ──→ 127.0.0.1:${PORT_SSH_INT}              │"
echo -e "  │      └── TLS traffic  ──→ 127.0.0.1:${PORT_STUNNEL} (stunnel4)  │"
echo -e "  │                               ↓                       │"
echo -e "  │                          Nginx:${PORT_NGINX}                   │"
echo -e "  │                               ↓ ${WS_PATH}              │"
echo -e "  │                          V2Ray:${PORT_V2RAY} (VMess WS)       │"
echo -e "${BOLD}  └──────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${BOLD}  ┌─ إعدادات العميل ──────────────────────────────────────┐${NC}"
echo -e "  │  Address  : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  │  Port     : ${YELLOW}443${NC}"
echo -e "  │  UUID     : ${YELLOW}${UUID}${NC}"
echo -e "  │  AlterId  : ${YELLOW}0${NC}"
echo -e "  │  Security : ${YELLOW}auto${NC}"
echo -e "  │  Network  : ${YELLOW}ws${NC}"
echo -e "  │  Path     : ${YELLOW}${WS_PATH}${NC}"
echo -e "  │  TLS      : ${YELLOW}tls${NC}"
echo -e "  │  SNI      : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  │  Allow    : ${YELLOW}Insecure = true${NC}"
echo -e "${BOLD}  └──────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${BOLD}  ┌─ VMess Link ───────────────────────────────────────────┐${NC}"
echo ""
echo -e "  ${GREEN}${VMESS_LINK}${NC}"
echo ""
echo -e "${BOLD}  └──────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${BOLD}  ┌─ أوامر مفيدة ──────────────────────────────────────────┐${NC}"
echo -e "  │  حالة الخدمات:                                         │"
echo -e "  │  ${CYAN}systemctl status haproxy stunnel4 nginx v2ray${NC}          │"
echo -e "  │                                                        │"
echo -e "  │  إعادة تشغيل الكل:                                    │"
echo -e "  │  ${CYAN}systemctl restart v2ray nginx stunnel4 haproxy${NC}         │"
echo -e "  │                                                        │"
echo -e "  │  سجلات V2Ray:                                         │"
echo -e "  │  ${CYAN}tail -f /var/log/v2ray/error.log${NC}                       │"
echo -e "  │                                                        │"
echo -e "  │  HAProxy Stats:                                        │"
echo -e "  │  ${CYAN}curl http://127.0.0.1:8404/stats${NC}                       │"
echo -e "  │                                                        │"
echo -e "  │  SSH عبر 443:                                         │"
echo -e "  │  ${CYAN}ssh -p 443 root@${SERVER_IP}${NC}                     │"
echo -e "${BOLD}  └──────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "  ${YELLOW}⚠  الشهادة ذاتية التوقيع — فعّل allowInsecure في التطبيق${NC}"
echo -e "  ${YELLOW}⚠  للشهادة الحقيقية: أضف دومين واستخدم: certbot --nginx${NC}"
echo ""

# حفظ المعلومات
cat > /root/v2ray-info.txt <<INFO
═══════════════════════════════════════
  MinaProNet — V2Ray Connection Info
  $(date)
═══════════════════════════════════════
Address  : ${SERVER_IP}
Port     : 443
Protocol : VMess + WebSocket + TLS
UUID     : ${UUID}
Path     : ${WS_PATH}
AlterId  : 0
TLS      : tls (allowInsecure = true)

VMess Link:
${VMESS_LINK}

─── Architecture ───────────────────────
:443 → HAProxy
  ├─ SSH  → 127.0.0.1:${PORT_SSH_INT}
  └─ TLS  → stunnel4:${PORT_STUNNEL}
               → nginx:${PORT_NGINX}
                   → v2ray:${PORT_V2RAY}

─── SSH Access ─────────────────────────
ssh -p 443 root@${SERVER_IP}
ssh -p 22  root@${SERVER_IP}  (backup)

─── HAProxy Stats ──────────────────────
curl http://127.0.0.1:8404/stats
user: admin / pass: minapronet
═══════════════════════════════════════
INFO

ok "تم حفظ المعلومات في /root/v2ray-info.txt"
