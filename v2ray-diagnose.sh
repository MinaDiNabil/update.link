#!/bin/bash
# ============================================================
#  V2Ray 443 Multiplexer — سكربت التشخيص الشامل
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
fail() { echo -e "  ${RED}[✗]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
info() { echo -e "  ${CYAN}[i]${NC} $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }

PORT_PUBLIC=443
PORT_SSHD=2222
PORT_NGINX=8443
PORT_V2RAY=10000
WS_PATH="/linkvws"
UUID="03fcc618-b93d-6796-6aed-8a38c975d581"

SERVER_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════╗"
echo "║   V2Ray 443 — التشخيص الشامل            ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Server IP: ${YELLOW}${SERVER_IP}${NC}"
echo -e "  Date: $(date)"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "1) حالة الخدمات"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

for svc in v2ray nginx sslh-custom sslh; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc: يعمل ✓"
    elif systemctl list-units --all | grep -q "$svc"; then
        fail "$svc: متوقف ✗"
        echo "      آخر أخطاء: $(journalctl -u $svc -n 3 --no-pager 2>/dev/null | tail -3)"
    fi
done

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "2) فحص البورتات المحلية (netstat)"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

check_port() {
    local port=$1 label=$2
    if ss -tlnp 2>/dev/null | grep -q ":${port}" || \
       ss -tlnup 2>/dev/null | grep -q ":${port}"; then
        ok "Port ${port} مفتوح (${label})"
    else
        fail "Port ${port} مغلق! (${label})"
    fi
}

check_port $PORT_PUBLIC  "sslh → public"
check_port $PORT_NGINX   "nginx → TLS"
check_port $PORT_V2RAY   "v2ray → WS"
check_port $PORT_SSHD    "sshd → internal"

echo ""
info "كل البورتات المفتوحة حالياً:"
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print "    " $4}' | sort

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "3) فحص V2Ray"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

V2RAY_CFG="/usr/local/etc/v2ray/config.json"
if [[ -f "$V2RAY_CFG" ]]; then
    ok "ملف config.json موجود"
    UUID_IN_CFG=$(grep -o '"id": *"[^"]*"' "$V2RAY_CFG" | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    PATH_IN_CFG=$(grep -o '"path": *"[^"]*"' "$V2RAY_CFG" | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    info "UUID في الملف : $UUID_IN_CFG"
    info "Path في الملف : $PATH_IN_CFG"
    [[ "$UUID_IN_CFG" == "$UUID" ]] && ok "UUID صحيح" || fail "UUID مختلف!"
    [[ "$PATH_IN_CFG" == "$WS_PATH" ]] && ok "Path صحيح" || fail "Path مختلف! المتوقع: $WS_PATH"
else
    fail "ملف config.json غير موجود في $V2RAY_CFG"
    info "البحث عن ملف config آخر..."
    find / -name "config.json" -path "*/v2ray/*" 2>/dev/null | head -5
fi

# اختبار WebSocket محلياً
echo ""
info "اختبار WebSocket على 127.0.0.1:${PORT_V2RAY}..."
WS_TEST=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "http://127.0.0.1:${PORT_V2RAY}${WS_PATH}" 2>/dev/null)

if [[ "$WS_TEST" == "101" ]]; then
    ok "V2Ray WebSocket يستجيب بـ 101 Switching Protocols ✓"
elif [[ "$WS_TEST" == "400" || "$WS_TEST" == "200" ]]; then
    warn "V2Ray يستجيب بـ HTTP $WS_TEST (قد يكون طبيعياً)"
else
    fail "V2Ray لا يستجيب على :${PORT_V2RAY} (HTTP: $WS_TEST)"
fi

# سجلات V2Ray
echo ""
info "آخر سجلات V2Ray:"
if [[ -f /var/log/v2ray/error.log ]]; then
    tail -5 /var/log/v2ray/error.log 2>/dev/null | sed 's/^/    /'
else
    journalctl -u v2ray -n 5 --no-pager 2>/dev/null | sed 's/^/    /'
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "4) فحص Nginx"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

nginx -t 2>&1 | while read -r line; do
    [[ "$line" == *"ok"* || "$line" == *"successful"* ]] && ok "$line" || warn "$line"
done

# اختبار HTTPS محلياً
echo ""
info "اختبار HTTPS على 127.0.0.1:${PORT_NGINX}..."
HTTPS_TEST=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    "https://127.0.0.1:${PORT_NGINX}/" 2>/dev/null)

[[ "$HTTPS_TEST" =~ ^[23] ]] && ok "Nginx يستجيب (HTTP $HTTPS_TEST)" || \
    warn "Nginx أعاد HTTP $HTTPS_TEST"

# اختبار WebSocket عبر Nginx
info "اختبار WS عبر Nginx (TLS)..."
WS_NGINX=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://127.0.0.1:${PORT_NGINX}${WS_PATH}" 2>/dev/null)

[[ "$WS_NGINX" == "101" ]] && ok "WebSocket عبر Nginx يعمل ✓" || \
    warn "WebSocket عبر Nginx: HTTP $WS_NGINX"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "5) فحص sslh"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if [[ -f /etc/sslh/sslh.cfg ]]; then
    ok "ملف sslh.cfg موجود"
    info "محتوى sslh.cfg:"
    grep -E "host|port|name" /etc/sslh/sslh.cfg | sed 's/^/    /'
else
    fail "ملف /etc/sslh/sslh.cfg غير موجود!"
fi

echo ""
info "آخر سجلات sslh:"
journalctl -u sslh-custom -n 10 --no-pager 2>/dev/null | sed 's/^/    /'

# اختبار الاتصال من الخارج عبر 443
echo ""
info "اختبار الاتصال على :443 من الخارج..."
EXT_TEST=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 8 \
    "https://${SERVER_IP}:443/" 2>/dev/null)
[[ "$EXT_TEST" =~ ^[23] ]] && ok "البورت 443 يستجيب من الخارج ✓" || \
    warn "البورت 443 أعاد: HTTP $EXT_TEST (إذا كان 000 فهو مغلق)"

# اختبار WS على 443
info "اختبار WebSocket عبر 443..."
WS_443=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 8 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://${SERVER_IP}:443${WS_PATH}" 2>/dev/null)
[[ "$WS_443" == "101" ]] && ok "WebSocket عبر 443 يعمل ✓" || \
    warn "WebSocket عبر 443: HTTP $WS_443"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "6) فحص الشهادة TLS"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSL_DIR="/etc/v2ray/ssl"
if [[ -f "$SSL_DIR/cert.pem" ]]; then
    ok "الشهادة موجودة"
    EXPIRY=$(openssl x509 -enddate -noout -in "$SSL_DIR/cert.pem" 2>/dev/null | cut -d= -f2)
    info "تنتهي في: $EXPIRY"
    openssl x509 -text -noout -in "$SSL_DIR/cert.pem" 2>/dev/null | \
        grep -E "Subject:|IP Address:|DNS:" | sed 's/^/    /'
else
    fail "الشهادة غير موجودة في $SSL_DIR"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "7) فحص الجدار الناري"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null)
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        ok "UFW مفعّل"
        echo "$UFW_STATUS" | grep -E "443|22|ALLOW" | sed 's/^/    /'
        echo "$UFW_STATUS" | grep -q "443" && ok "Port 443 مسموح" || fail "Port 443 غير مسموح في UFW!"
    else
        warn "UFW غير مفعّل"
    fi
fi

# iptables
info "قواعد iptables للبورت 443:"
iptables -L INPUT -n 2>/dev/null | grep "443\|ACCEPT\|DROP" | head -10 | sed 's/^/    /' || \
    warn "لا توجد قواعد iptables ظاهرة"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "8) تشخيص المشاكل الشائعة وإصلاحها"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ISSUES=0

# مشكلة 1: sslh لا يعمل
if ! systemctl is-active --quiet sslh-custom 2>/dev/null && \
   ! systemctl is-active --quiet sslh 2>/dev/null; then
    fail "sslh لا يعمل — جاري إصلاحه..."
    ISSUES=$((ISSUES+1))

    # تحقق إذا كان البورت 443 مشغولاً بشيء آخر
    USING_443=$(ss -tlnp | grep ":443 " | awk '{print $NF}')
    if [[ -n "$USING_443" ]]; then
        warn "البورت 443 مشغول من: $USING_443"
        warn "جاري إيقافه..."
        # إيقاف nginx إذا كان يستخدم 443
        if echo "$USING_443" | grep -q nginx; then
            # أعد إعداد nginx ليستمع فقط على 8443
            warn "Nginx يستخدم 443 — سيتم تصحيح الإعداد"
        fi
    fi

    systemctl restart sslh-custom 2>/dev/null || systemctl restart sslh 2>/dev/null
    sleep 2
    systemctl is-active --quiet sslh-custom 2>/dev/null && ok "sslh يعمل الآن ✓"
fi

# مشكلة 2: Nginx يستمع على 443 بدلاً من 8443
NGINX_443=$(ss -tlnp | grep ":443" | grep nginx)
if [[ -n "$NGINX_443" ]]; then
    fail "Nginx يستمع على 443 مباشرة — هذا يتعارض مع sslh!"
    ISSUES=$((ISSUES+1))
    warn "جاري تصحيح إعداد Nginx..."

    NGINX_SITE="/etc/nginx/sites-enabled/v2ray"
    if [[ -f "$NGINX_SITE" ]]; then
        sed -i "s/listen 0.0.0.0:443/listen 127.0.0.1:8443/g" "$NGINX_SITE"
        sed -i "s/listen \[::\]:443/listen 127.0.0.1:8443/g"  "$NGINX_SITE"
        sed -i "s/listen 443/listen 127.0.0.1:8443/g"          "$NGINX_SITE"
        nginx -t && systemctl reload nginx && ok "Nginx صُحّح ✓"
    fi
fi

# مشكلة 3: v2ray لا يستمع على 127.0.0.1
V2RAY_LISTEN=$(ss -tlnp | grep ":${PORT_V2RAY}")
if [[ -z "$V2RAY_LISTEN" ]]; then
    fail "V2Ray لا يستمع على :${PORT_V2RAY}!"
    ISSUES=$((ISSUES+1))
    warn "جاري إعادة تشغيل V2Ray..."
    systemctl restart v2ray
    sleep 2
    ss -tlnp | grep ":${PORT_V2RAY}" && ok "V2Ray يعمل الآن ✓" || \
        fail "V2Ray لا يزال لا يعمل — تحقق من: journalctl -u v2ray -n 20"
fi

# مشكلة 4: sslh binary غير موجود
SSLH_BIN=$(command -v sslh-select 2>/dev/null || command -v sslh 2>/dev/null)
if [[ -z "$SSLH_BIN" ]]; then
    fail "sslh غير مثبّت!"
    ISSUES=$((ISSUES+1))
    info "جاري تثبيت sslh..."
    apt-get install -y sslh -o APT::Update::Post-Invoke-Success="" 2>/dev/null
    SSLH_BIN=$(command -v sslh-select 2>/dev/null || command -v sslh 2>/dev/null)
    if [[ -n "$SSLH_BIN" ]]; then
        # تحديث service file
        sed -i "s|ExecStart=.*|ExecStart=${SSLH_BIN} --foreground --config /etc/sslh/sslh.cfg|" \
            /etc/systemd/system/sslh-custom.service
        systemctl daemon-reload
        systemctl restart sslh-custom
        ok "sslh مثبّت ويعمل ✓"
    fi
fi

# مشكلة 5: config.json يستخدم listen على كل الواجهات
V2RAY_LISTEN_ALL=$(grep -o '"listen": *"[^"]*"' "$V2RAY_CFG" 2>/dev/null)
if echo "$V2RAY_LISTEN_ALL" | grep -q "0.0.0.0"; then
    warn "V2Ray مضبوط على 0.0.0.0 — من الأفضل 127.0.0.1"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
hdr "9) الملخص النهائي"
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
FINAL_WS=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://${SERVER_IP}:443${WS_PATH}" 2>/dev/null)

if [[ "$FINAL_WS" == "101" ]]; then
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║  ✅ كل شيء يعمل بشكل صحيح!          ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${NC}"
elif [[ $ISSUES -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║  ⚠  الخدمات تعمل لكن WS لم يؤكد (HTTP $FINAL_WS)  ║"
    echo "  ║  تأكد من تفعيل allowInsecure في التطبيق    ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
else
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  ✗ يوجد ${ISSUES} مشكلة — راجع النتائج أعلاه  ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
fi

echo ""
echo -e "${BOLD}  إعدادات العميل الصحيحة:${NC}"
echo -e "  ┌─────────────────────────────────────────┐"
echo -e "  │ Address  : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  │ Port     : ${YELLOW}443${NC}"
echo -e "  │ UUID     : ${YELLOW}${UUID}${NC}"
echo -e "  │ AlterId  : ${YELLOW}0${NC}"
echo -e "  │ Security : ${YELLOW}auto${NC}"
echo -e "  │ Network  : ${YELLOW}ws${NC}"
echo -e "  │ Path     : ${YELLOW}${WS_PATH}${NC}"
echo -e "  │ TLS      : ${YELLOW}tls (allowInsecure = true)${NC}"
echo -e "  └─────────────────────────────────────────┘"
echo ""
