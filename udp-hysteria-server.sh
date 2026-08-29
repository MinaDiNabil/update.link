#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — إصلاح التصفح: تشغيل badvpn-udpgw
#
#  السبب المؤكَّد من سجل السيرفر:
#     [dst:127.0.0.1:7300] [error:dial tcp 127.0.0.1:7300: connection refused]
#
#  التطبيق يمرّر TCP عبر نفق hysteria، لكنه يمرّر كل حركة UDP — وأولها
#  استعلامات DNS — عبر badvpn-udpgw على 127.0.0.1:7300 داخل السيرفر.
#  المنفذ فارغ، فتُرفض استعلامات DNS، فلا يُترجم أي اسم، فلا يفتح أي موقع،
#  بينما يبقى النفق قائماً ويظهر التطبيق "متصلاً".
#
#  هذه النسخة تختبر التشغيل يدوياً أولاً وتلتقط الخطأ الحقيقي، ثم تبني
#  الخدمة بالإعدادات التي ثبت نجاحها فقط — بدل الافتراض.
#
#  الاستخدام:  sudo bash udpgw-setup.sh
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:$PATH"

UDPGW_PORT="${UDPGW_PORT:-auto}"
MAX_CLIENTS="${MAX_CLIENTS:-1000}"
MAX_CONN_PER_CLIENT="${MAX_CONN_PER_CLIENT:-10}"
SVC="hysteria-server"

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "يجب تشغيل السكربت بصلاحيات root."

tcp_ok() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

# ==================== ١) المنفذ الذي يطلبه التطبيق ====================
if [ "$UDPGW_PORT" = "auto" ]; then
    log "قراءة سجل hysteria لمعرفة المنفذ الذي يطلبه التطبيق..."
    DETECTED=$(journalctl -u "$SVC" -n 5000 --no-pager 2>/dev/null \
        | grep -oE 'dst:127\.0\.0\.1:[0-9]+' \
        | grep -oE '[0-9]+$' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || true)
    if [ -n "${DETECTED:-}" ]; then
        UDPGW_PORT="$DETECTED"
        ok "المنفذ المكتشف من طلبات المستخدمين: ${UDPGW_PORT}"
    else
        UDPGW_PORT=7300
        warn "لا توجد طلبات في السجل — سيُستخدم المنفذ القياسي 7300."
    fi
fi
case "$UDPGW_PORT" in ''|*[!0-9]*) die "منفذ غير صالح: $UDPGW_PORT";; esac

# ==================== ٢) هل الخدمة متوفرة أصلاً؟ ====================
if tcp_ok 127.0.0.1 "$UDPGW_PORT"; then
    ok "يوجد بالفعل من يستمع على 127.0.0.1:${UDPGW_PORT}"
    ss -ltnp 2>/dev/null | grep -E "[:.]${UDPGW_PORT}[[:space:]]" | sed 's/^/    /'
    warn "لا حاجة لإنشاء خدمة جديدة. إن استمرت مشكلة التصفح فالسبب في مكان آخر."
    exit 0
fi

# ==================== ٣) إيجاد الملف التنفيذي ====================
find_udpgw() {
    local p
    for p in /usr/local/bin/badvpn-udpgw /usr/bin/badvpn-udpgw; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    command -v badvpn-udpgw 2>/dev/null && return 0
    return 1
}

UDPGW_BIN="$(find_udpgw || true)"
if [ -z "${UDPGW_BIN:-}" ]; then
    log "تركيب badvpn من المستودعات..."
    (DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1 \
     || (timeout 240 apt-get update >/dev/null 2>&1 \
         && DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1)) || true
    hash -r 2>/dev/null || true
    UDPGW_BIN="$(find_udpgw || true)"
fi
if [ -z "${UDPGW_BIN:-}" ]; then
    log "بناؤه من المصدر..."
    (DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y \
        cmake make gcc git libssl-dev >/dev/null 2>&1) || true
    BUILD=$(mktemp -d /tmp/badvpn.XXXXXX)
    if timeout 180 git clone --depth 1 https://github.com/ambrop72/badvpn.git "$BUILD/src" >/dev/null 2>&1; then
        mkdir -p "$BUILD/b"
        (cd "$BUILD/b" && cmake ../src -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1 \
            && make >/dev/null 2>&1 && make install >/dev/null 2>&1) || true
        hash -r 2>/dev/null || true
        UDPGW_BIN="$(find_udpgw || true)"
    fi
    rm -rf "$BUILD"
fi
[ -n "${UDPGW_BIN:-}" ] || die "تعذّر تركيب badvpn-udpgw. جرّب: apt update && apt install -y badvpn"
ok "الملف التنفيذي: ${UDPGW_BIN}"

# ==================== ٤) من يحتجز المنفذ على أي عنوان ====================
HOLDERS=$(ss -ltnp 2>/dev/null | grep -E "[:.]${UDPGW_PORT}[[:space:]]" || true)
if [ -n "$HOLDERS" ]; then
    warn "المنفذ ${UDPGW_PORT} محتجَز رغم رفضه الاتصال:"
    echo "$HOLDERS" | sed 's/^/    /'
    for pid in $(echo "$HOLDERS" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        exe=$(readlink -f /proc/"$pid"/exe 2>/dev/null || echo '?')
        warn "  إيقاف العملية ${pid} (${exe})"
        kill "$pid" 2>/dev/null || true
    done
    sleep 2
fi

# ==================== ٥) اختبار التشغيل يدوياً لالتقاط الخطأ ====================
# نجرّب المعاملات الكاملة ثم المبسّطة. الرمز 124 يعني أن العملية بقيت تعمل.
MANUAL_OUT=""
WORKING_ARGS=""
try_run() {
    local desc="$1"; shift
    local out rc=0
    out=$(timeout 3 "$UDPGW_BIN" "$@" 2>&1) || rc=$?
    MANUAL_OUT="$out"
    if [ "$rc" -eq 124 ]; then
        ok "نجح التشغيل اليدوي (${desc})"
        WORKING_ARGS="$*"
        return 0
    fi
    warn "فشل (${desc}): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-120)"
    return 1
}

log "اختبار تشغيل udpgw يدوياً..."
if   try_run "معاملات كاملة" --listen-addr "127.0.0.1:${UDPGW_PORT}" \
        --max-clients "$MAX_CLIENTS" --max-connections-for-client "$MAX_CONN_PER_CLIENT" \
        --loglevel warning; then :
elif try_run "بلا loglevel" --listen-addr "127.0.0.1:${UDPGW_PORT}" \
        --max-clients "$MAX_CLIENTS" --max-connections-for-client "$MAX_CONN_PER_CLIENT"; then :
elif try_run "معاملات مبسّطة" --listen-addr "127.0.0.1:${UDPGW_PORT}"; then :
elif try_run "على كل العناوين" --listen-addr "0.0.0.0:${UDPGW_PORT}" \
        --max-clients "$MAX_CLIENTS" --max-connections-for-client "$MAX_CONN_PER_CLIENT"; then
    warn "الارتباط بـ 127.0.0.1 فشل — سيُستخدم 0.0.0.0 مع حجب المنفذ من الخارج."
    BLOCK_EXTERNAL=1
else
    echo
    echo "آخر خطأ من udpgw:"; printf '%s\n' "$MANUAL_OUT" | sed 's/^/    /'
    echo
    echo "المنفذ ${UDPGW_PORT} على كل العناوين:"
    ss -ltnp 2>/dev/null | grep -E "[:.]${UDPGW_PORT}[[:space:]]" | sed 's/^/    /' || echo "    (فارغ)"
    die "تعذّر تشغيل udpgw بأي إعداد."
fi

# ==================== ٦) وحدة systemd بلا عزل ====================
# النسخة السابقة فشلت بسبب User=nobody و ProtectSystem=strict
# و RestrictAddressFamilies. udpgw يستمع على اللوبباك فقط ولا يحتاج عزلاً.
log "إنشاء خدمة badvpn-udpgw..."
cat > /etc/systemd/system/badvpn-udpgw.service <<EOF
[Unit]
Description=BadVPN udpgw - UDP forwarding for VPN clients
Documentation=https://github.com/ambrop72/badvpn
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
ExecStart=${UDPGW_BIN} ${WORKING_ARGS}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF

mkdir -p "/etc/systemd/system/${SVC}.service.d"
cat > "/etc/systemd/system/${SVC}.service.d/udpgw.conf" <<EOF
[Unit]
Wants=badvpn-udpgw.service
After=badvpn-udpgw.service
EOF

systemctl daemon-reload
systemctl reset-failed badvpn-udpgw.service >/dev/null 2>&1 || true
systemctl enable badvpn-udpgw.service >/dev/null 2>&1 || true
systemctl restart badvpn-udpgw.service

# ==================== ٧) الجدار الناري ====================
iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT >/dev/null 2>&1
if [ "${BLOCK_EXTERNAL:-0}" = "1" ]; then
    IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    if [ -n "${IFACE:-}" ]; then
        iptables -C INPUT -i "$IFACE" -p tcp --dport "$UDPGW_PORT" -j DROP >/dev/null 2>&1 \
            || iptables -I INPUT 1 -i "$IFACE" -p tcp --dport "$UDPGW_PORT" -j DROP >/dev/null 2>&1
        ok "حُجب المنفذ ${UDPGW_PORT} من الخارج"
    fi
fi

# ==================== ٨) تشغيل hysteria ====================
if ! systemctl is-active --quiet "$SVC"; then
    log "تشغيل خدمة hysteria..."
    systemctl reset-failed "$SVC" >/dev/null 2>&1 || true
    systemctl start "$SVC" >/dev/null 2>&1 || true
fi

# ==================== ٩) التحقق ====================
log "التحقق..."
sleep 4
FAIL=0

if systemctl is-active --quiet badvpn-udpgw.service; then
    ok "خدمة udpgw تعمل"
else
    warn "خدمة udpgw متوقفة:"
    journalctl -u badvpn-udpgw.service -n 12 --no-pager | sed 's/^/    /' || true
    FAIL=1
fi

if tcp_ok 127.0.0.1 "$UDPGW_PORT"; then
    ok "الاتصال بـ 127.0.0.1:${UDPGW_PORT} ناجح — لن تُرفض طلبات المستخدمين"
else
    warn "ما زال الاتصال بالمنفذ ${UDPGW_PORT} فاشلاً"
    FAIL=1
fi

if systemctl is-active --quiet "$SVC"; then
    ok "خدمة hysteria تعمل"
else
    warn "خدمة hysteria متوقفة:"
    journalctl -u "$SVC" -n 12 --no-pager | sed 's/^/    /' || true
    FAIL=1
fi

echo
if [ "$FAIL" = "0" ]; then
    echo "════════════════════════════════════════════════════"
    echo " جاهز. افتح التطبيق واتصل ثم جرّب التصفح."
    echo
    echo " لمراقبة الطلبات لحظياً:"
    echo "   journalctl -u ${SVC} -f"
    echo
    echo " يجب أن تختفي أسطر connection refused، وتظهر بدلاً"
    echo " منها وجهات حقيقية مثل  dst:142.250.x.x:443"
    echo "════════════════════════════════════════════════════"
else
    die "بقيت مشكلة — راجع المخرجات أعلاه."
fi
