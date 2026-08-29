#!/usr/bin/env bash
# ==============================================================================
#  hy-test — اختبار التصفح عبر نفق Hysteria v1 وتحديد موضع العطل بدقة
#
#  يقرأ القيم من ملف الإعداد الحي (لا من قيم مخزّنة وقت التثبيت)، ثم:
#   اختبار أ: عميل ← السيرفر العامل على منفذه الحالي
#   اختبار ب: إن فشل أ، يشغّل سيرفراً مؤقتاً على منفذ حر ويعيد المحاولة
#  المقارنة بين النتيجتين تحدد السبب:
#   أ فشل + ب نجح  = الإعداد سليم والمشكلة في الخدمة العاملة أو مالك المنفذ
#   أ فشل + ب فشل  = مشكلة في الإعداد نفسه أو في ترشيح حزم اللوبباك
#   أ نجح          = النفق سليم، ويُختبر التصفح فعلياً بعده
# ==============================================================================
set -uo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

HY_BIN="${HY_BIN:-/usr/local/bin/hysteria}"
CFGF="${CFGF:-/etc/hysteria/config.json}"
SVC="hysteria-server"

c_ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
c_bad()  { printf '\033[1;31m✗\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }
P() { printf '  %-42s %s\n' "$1" "$2"; }

[ "$(id -u)" -eq 0 ] || { echo "شغّله بصلاحيات root"; exit 2; }
[ -r "$CFGF" ] || { c_bad "لا يوجد ملف إعداد في $CFGF"; exit 2; }
command -v curl >/dev/null 2>&1 || { c_bad "curl غير مثبت: apt install -y curl"; exit 2; }

# ---------------- قراءة القيم من الإعداد الحي ----------------
PORT=$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*":\([0-9]*\)".*/\1/p'   "$CFGF" | head -1)
OBFS=$(sed -n 's/.*"obfs"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'       "$CFGF" | head -1)
UP=$(  sed -n 's/.*"up_mbps"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p'     "$CFGF" | head -1)
DOWN=$(sed -n 's/.*"down_mbps"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p'   "$CFGF" | head -1)
AUTH=$(sed -n 's/.*"config"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p' "$CFGF" | head -1)
[ -z "$AUTH" ] && AUTH=$(sed -n 's/.*"password"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFGF" | head -1)
[ -z "${UP:-}" ] && UP=100
[ -z "${DOWN:-}" ] && DOWN=100
[ -z "${PORT:-}" ] && { c_bad "تعذّر قراءة منفذ الاستماع من الإعداد"; exit 2; }

echo "════════════ ١. من يملك المنفذ ${PORT} ════════════"
P "الخدمة نشطة:" "$(systemctl is-active $SVC 2>/dev/null)"
OWNER_OK=0
PIDS=$(ss -lunp 2>/dev/null | grep -E "[:*.]${PORT}[[:space:]]" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
if [ -z "$PIDS" ]; then
    c_bad "لا شيء يستمع على ${PORT} — الخدمة ليست قيد التشغيل"
else
    for pid in $PIDS; do
        exe=$(readlink -f /proc/"$pid"/exe 2>/dev/null || echo '?')
        unit=$(sed -n 's|.*/system\.slice/\([^/]*\.service\).*|\1|p' /proc/"$pid"/cgroup 2>/dev/null | head -1)
        P "العملية ${pid}:" "${exe}${unit:+  [${unit}]}"
        if [ "$exe" = "$(readlink -f "$HY_BIN" 2>/dev/null)" ] && [ "${unit:-}" = "${SVC}.service" ]; then
            OWNER_OK=1
        fi
    done
    if [ "$OWNER_OK" = "1" ]; then
        c_ok "المنفذ يملكه سيرفر hysteria الخاص بنا"
    else
        c_bad "المنفذ يملكه برنامج آخر! هذا يفسّر عدم استجابة السيرفر."
        echo "     الحل: أعد تشغيل سكربت التثبيت — سيحرّر المنفذ أو ينقل الخدمة لمنفذ آخر."
    fi
fi
echo

# ---------------- دالة اختبار العميل ----------------
run_client() {   # $1 = عنوان السيرفر ، $2 = ملف السجل
    local addr="$1" logf="$2" socks cfg obfsline=""
    socks=11080
    while ss -ltn 2>/dev/null | grep -qE "[:*.]${socks}[[:space:]]"; do socks=$((socks+1)); done
    cfg=$(mktemp /tmp/hy-cli.XXXXXX.json)
    [ -n "${OBFS:-}" ] && obfsline="\"obfs\": \"${OBFS}\","
    cat > "$cfg" <<CFGEOF
{
    "server": "${addr}",
    "protocol": "udp",
    ${obfsline}
    "auth_str": "${AUTH}",
    "up_mbps": ${UP},
    "down_mbps": ${DOWN},
    "insecure": true,
    "server_name": "www.bing.com",
    "handshake_timeout": 10,
    "socks5": { "listen": "127.0.0.1:${socks}" }
}
CFGEOF
    "$HY_BIN" client --config "$cfg" >"$logf" 2>&1 &
    CLIENT_PID=$!
    local i
    for i in $(seq 1 20); do
        ss -ltn 2>/dev/null | grep -qE "[:*.]${socks}[[:space:]]" && { SOCKS_PORT="$socks"; rm -f "$cfg"; return 0; }
        kill -0 "$CLIENT_PID" 2>/dev/null || break
        sleep 1
    done
    rm -f "$cfg"
    kill "$CLIENT_PID" 2>/dev/null
    return 1
}

CLIENT_PID=""; SOCKS_PORT=""; TMPSRV_PID=""
cleanup() {
    [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -n "${TMPSRV_PID:-}" ] && kill "$TMPSRV_PID" 2>/dev/null
    rm -f /tmp/hy-cli.*.log /tmp/hy-srv.*.json /tmp/hy-srv.*.log 2>/dev/null
    return 0
}
trap cleanup EXIT

echo "════════════ ٢. اختبار النفق ════════════"
LOGA=$(mktemp /tmp/hy-cli.XXXXXX.log)
if run_client "127.0.0.1:${PORT}" "$LOGA"; then
    c_ok "النفق قائم والمصادقة ناجحة"
    TUNNEL=1
else
    c_bad "العميل لم يتصل بالسيرفر العامل"
    echo "  سجل العميل:"; tail -6 "$LOGA" | sed 's/^/    /'
    TUNNEL=0

    # ---- اختبار ب: سيرفر مؤقت على منفذ حر ----
    echo
    echo "  تشغيل سيرفر مؤقت على منفذ حر لعزل السبب..."
    TP=41000
    while ss -lun 2>/dev/null | grep -qE "[:*.]${TP}[[:space:]]"; do TP=$((TP+1)); done
    TSCFG=$(mktemp /tmp/hy-srv.XXXXXX.json)
    TSLOG=$(mktemp /tmp/hy-srv.XXXXXX.log)
    sed "s/\"listen\"[[:space:]]*:[[:space:]]*\":[0-9]*\"/\"listen\": \":${TP}\"/" "$CFGF" > "$TSCFG"
    "$HY_BIN" server --config "$TSCFG" >"$TSLOG" 2>&1 &
    TMPSRV_PID=$!
    sleep 3
    LOGB=$(mktemp /tmp/hy-cli.XXXXXX.log)
    if run_client "127.0.0.1:${TP}" "$LOGB"; then
        c_ok "السيرفر المؤقت اتصل بنجاح على المنفذ ${TP}"
        echo
        c_warn "النتيجة: ملف الإعداد سليم تماماً."
        echo "  العطل في الخدمة العاملة أو في مالك المنفذ ${PORT}."
        echo "  الحل: أعد تشغيل سكربت التثبيت لتحرير المنفذ أو نقل الخدمة."
        kill "$CLIENT_PID" 2>/dev/null; CLIENT_PID=""
        TUNNEL=2
    else
        c_bad "السيرفر المؤقت فشل أيضاً"
        echo "  سجل السيرفر المؤقت:"; tail -6 "$TSLOG" | sed 's/^/    /'
        echo "  سجل العميل:";        tail -6 "$LOGB" | sed 's/^/    /'
        echo
        c_warn "النتيجة: العطل في الإعداد نفسه أو في ترشيح حزم اللوبباك."
        echo "  افحص:  iptables -L INPUT -n -v | head"
        echo "         iptables -L HY_IN -n -v"
    fi
    kill "$TMPSRV_PID" 2>/dev/null; TMPSRV_PID=""
    rm -f "$TSCFG"
fi

# ---------------- اختبار التصفح ----------------
if [ "${TUNNEL:-0}" = "1" ]; then
    echo
    echo "════════════ ٣. التصفح عبر النفق ════════════"
    R1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
          --socks5-hostname 127.0.0.1:"$SOCKS_PORT" https://www.google.com 2>/dev/null || echo 000)
    R2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
          --socks5 127.0.0.1:"$SOCKS_PORT" https://www.google.com 2>/dev/null || echo 000)
    R3=$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 \
          --socks5-hostname 127.0.0.1:"$SOCKS_PORT" https://www.youtube.com 2>/dev/null || echo 000)
    P "google.com (الترجمة داخل السيرفر):" "$R1"
    P "google.com (الترجمة محلياً):"       "$R2"
    P "youtube.com:"                       "$R3"
    echo
    if [ "$R1" != "000" ] && [ "$R3" != "000" ]; then
        c_ok "التصفح عبر النفق يعمل. السيرفر سليم تماماً."
        echo "  إن كان التطبيق لا يتصفح فالمشكلة في مسار القفز أو في التطبيق."
        echo "  تأكد أن UDP Port في التطبيق يطابق:"
        iptables -t nat -S HY_HOP 2>/dev/null | grep -oE 'dports? [0-9:]+' | tail -1 | sed 's/^/    /'
    elif [ "$R2" != "000" ] && [ "$R1" = "000" ]; then
        c_bad "خروج السيرفر سليم لكن ترجمة الأسماء داخله فاشلة."
        echo "  الحل: sudo RESOLVER=\"udp://8.8.8.8:53\" bash udp-hysteria-server.sh"
    else
        c_bad "السيرفر لا يصل إلى الإنترنت نيابةً عن المستخدمين."
        echo "  سجل العميل:"; tail -8 "$LOGA" | sed 's/^/    /'
    fi
fi

echo
echo "════════════ ٤. سجل السيرفر ════════════"
journalctl -u "$SVC" -n 8 --no-pager 2>/dev/null | sed 's/^/  /' || true
