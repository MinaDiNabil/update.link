#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — إصلاح التصفح: تركيب badvpn-udpgw
#
#  السبب المؤكَّد من سجل السيرفر:
#     [dst:127.0.0.1:7300] [error:dial tcp 127.0.0.1:7300: connection refused]
#
#  تطبيقك يمرّر حركة TCP عبر نفق hysteria، لكنه يمرّر حركة UDP كاملةً
#  (وأولها استعلامات DNS) عبر badvpn-udpgw على المنفذ 127.0.0.1:7300 داخل
#  السيرفر. هذا المنفذ فارغ، فتُرفض كل استعلامات DNS، فلا يُترجم أي اسم نطاق،
#  فلا يفتح أي موقع — بينما يبقى النفق نفسه قائماً ويظهر التطبيق "متصلاً".
#  لهذا لم تنفع كل محاولات إصلاح DNS و IPv6 و MTU: العطل لم يكن هناك أصلاً.
#
#  الاستخدام:  sudo bash udpgw-setup.sh
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

UDPGW_PORT="${UDPGW_PORT:-auto}"      # auto = كشف المنفذ من سجل hysteria
MAX_CLIENTS="${MAX_CLIENTS:-2000}"
MAX_CONN_PER_CLIENT="${MAX_CONN_PER_CLIENT:-20}"
SVC="hysteria-server"

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "يجب تشغيل السكربت بصلاحيات root."

# ==================== ١) تحديد المنفذ الذي يطلبه التطبيق ====================
if [ "$UDPGW_PORT" = "auto" ]; then
    log "قراءة سجل hysteria لمعرفة المنفذ الذي يطلبه التطبيق..."
    DETECTED=$(journalctl -u "$SVC" -n 5000 --no-pager 2>/dev/null \
        | grep -oE 'dst:127\.0\.0\.1:[0-9]+' \
        | grep -oE '[0-9]+$' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || true)
    if [ -n "${DETECTED:-}" ]; then
        UDPGW_PORT="$DETECTED"
        ok "المنفذ المكتشف من طلبات المستخدمين الفعلية: ${UDPGW_PORT}"
    else
        UDPGW_PORT=7300
        warn "لا توجد طلبات في السجل — سيُستخدم المنفذ القياسي 7300."
    fi
fi
case "$UDPGW_PORT" in ''|*[!0-9]*) die "منفذ غير صالح: $UDPGW_PORT";; esac

# ==================== ٢) تركيب badvpn-udpgw ====================
find_udpgw() {
    command -v badvpn-udpgw 2>/dev/null && return 0
    for p in /usr/bin/badvpn-udpgw /usr/local/bin/badvpn-udpgw; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
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
    log "غير متوفر في المستودعات — بناؤه من المصدر..."
    (DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y \
        cmake make gcc git libssl-dev >/dev/null 2>&1) || true
    BUILD=$(mktemp -d /tmp/badvpn.XXXXXX)
    if timeout 180 git clone --depth 1 https://github.com/ambrop72/badvpn.git "$BUILD/src" >/dev/null 2>&1; then
        mkdir -p "$BUILD/b"
        if (cd "$BUILD/b" && cmake ../src -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1 \
            && make >/dev/null 2>&1 && make install >/dev/null 2>&1); then
            hash -r 2>/dev/null || true
            UDPGW_BIN="$(find_udpgw || true)"
        fi
    fi
    rm -rf "$BUILD"
fi

[ -n "${UDPGW_BIN:-}" ] || die "تعذّر تركيب badvpn-udpgw. جرّب يدوياً:
  apt update && apt install -y badvpn"
ok "badvpn-udpgw موجود في ${UDPGW_BIN}"

# ==================== ٣) تحرير المنفذ إن كان مشغولاً بغير udpgw ====================
port_pids() {
    ss -ltnp 2>/dev/null | grep -E "127\.0\.0\.1:${1}[[:space:]]" \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true
}
for pid in $(port_pids "$UDPGW_PORT"); do
    exe=$(readlink -f /proc/"$pid"/exe 2>/dev/null || echo '?')
    case "$exe" in
        *badvpn-udpgw) : ;;   # نسخة قديمة، ستُستبدل بالخدمة
        *) warn "المنفذ ${UDPGW_PORT} يشغله ${exe} (pid ${pid})" ;;
    esac
done

# ==================== ٤) وحدة systemd ====================
log "إنشاء خدمة badvpn-udpgw..."
cat > /etc/systemd/system/badvpn-udpgw.service <<EOF
[Unit]
Description=BadVPN udpgw — تمرير UDP لعملاء VPN (يشمل DNS)
Documentation=https://github.com/ambrop72/badvpn
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${UDPGW_BIN} --listen-addr 127.0.0.1:${UDPGW_PORT} \\
    --max-clients ${MAX_CLIENTS} \\
    --max-connections-for-client ${MAX_CONN_PER_CLIENT} \\
    --loglevel warning
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
OOMScoreAdjust=-500
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

# ربط hysteria بها دون تعديل وحدتها الأصلية
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

# ==================== ٥) السماح بحركة اللوبباك ====================
# hysteria يتصل بـ 127.0.0.1:UDPGW_PORT من داخل السيرفر.
iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT >/dev/null 2>&1

# ==================== ٦) تشغيل hysteria ====================
if ! systemctl is-active --quiet "$SVC"; then
    log "خدمة hysteria متوقفة — تشغيلها..."
    systemctl reset-failed "$SVC" >/dev/null 2>&1 || true
    systemctl start "$SVC" >/dev/null 2>&1 || true
fi

# ==================== ٧) التحقق ====================
log "التحقق..."
sleep 3

FAIL=0
if systemctl is-active --quiet badvpn-udpgw.service \
   && ss -ltn 2>/dev/null | grep -qE "127\.0\.0\.1:${UDPGW_PORT}[[:space:]]"; then
    ok "udpgw يستمع على 127.0.0.1:${UDPGW_PORT}"
else
    warn "udpgw لم يعمل. السجل:"
    journalctl -u badvpn-udpgw.service -n 15 --no-pager || true
    FAIL=1
fi

if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${UDPGW_PORT}" >/dev/null 2>&1; then
    ok "الاتصال بالمنفذ ${UDPGW_PORT} ناجح — لن تُرفض طلبات المستخدمين بعد الآن"
else
    warn "تعذّر الاتصال بالمنفذ ${UDPGW_PORT} محلياً"
    FAIL=1
fi

if systemctl is-active --quiet "$SVC"; then
    ok "خدمة hysteria تعمل"
else
    warn "خدمة hysteria متوقفة. السجل:"
    journalctl -u "$SVC" -n 15 --no-pager || true
    FAIL=1
fi

echo
if [ "$FAIL" = "0" ]; then
    echo "════════════════════════════════════════════════════"
    echo " جاهز. افتح التطبيق واتصل ثم جرّب التصفح."
    echo
    echo " لمراقبة الطلبات لحظياً أثناء التصفح:"
    echo "   journalctl -u ${SVC} -f"
    echo
    echo " يجب أن تختفي أسطر connection refused تماماً،"
    echo " وتظهر بدلاً منها وجهات حقيقية مثل dst:142.250.x.x:443"
    echo "════════════════════════════════════════════════════"
else
    die "بقيت مشكلة — راجع المخرجات أعلاه."
fi
