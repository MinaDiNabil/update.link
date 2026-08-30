#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — إصلاح التصفح: تشغيل badvpn-udpgw
#
#  التشخيص المؤكَّد بالقياس:
#   • سجل hysteria:  dst:127.0.0.1:7300 → connection refused
#     التطبيق يمرّر كل حركة UDP (وأولها DNS) عبر udpgw على هذا المنفذ.
#   • اختبار python: errno=98 Address already in use
#   • ss -ltn:       فارغ
#
#  المنفذ 7300 محجوز فعلاً، لكن بمقبس TCP استُدعي عليه bind() دون listen().
#  هذا النوع موجود في جدول bhash فقط ولا يظهر في ss ولا netstat ولا lsof،
#  ولا يتجاوزه SO_REUSEADDR. لذلك فشل كل من python وbadvpn بالخطأ نفسه.
#
#  الحل: تشغيل udpgw على منفذ حر، وتحويل اتصالات hysteria الصادرة نحو
#  7300 إليه عبر سلسلة OUTPUT في جدول nat. hysteria يظل يطلب 7300 ولن
#  يلاحظ شيئاً. ويُحاول تحرير المنفذ أولاً قبل اللجوء للتحويل.
#
#  الاستخدام:  sudo bash udpgw-setup.sh
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:$PATH"

APP_PORT="${APP_PORT:-auto}"        # المنفذ الذي يطلبه التطبيق
MAX_CLIENTS="${MAX_CLIENTS:-1000}"
MAX_CONN_PER_CLIENT="${MAX_CONN_PER_CLIENT:-10}"
SVC="hysteria-server"
BUILD_PREFIX=/opt/badvpn
HELPER=/etc/hysteria/udpgw-redirect.sh

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "يجب تشغيل السكربت بصلاحيات root."
tcp_ok() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

# الفحص الوحيد الموثوق: محاولة ارتباط حقيقية
can_bind() {
    command -v python3 >/dev/null 2>&1 || return 0
    local r
    r=$(python3 - "$1" <<'PY' 2>&1 || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1); print("OK")
except OSError as e:
    print("FAIL errno=%d %s" % (e.errno, e.strerror))
finally:
    s.close()
PY
)
    BIND_RESULT="$r"
    case "$r" in OK*) return 0;; *) return 1;; esac
}

# ==================== ١) المنفذ الذي يطلبه التطبيق ====================
if [ "$APP_PORT" = "auto" ]; then
    log "قراءة سجل hysteria..."
    D=$(journalctl -u "$SVC" -n 5000 --no-pager 2>/dev/null \
        | grep -oE 'dst:127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' \
        | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || true)
    if [ -n "${D:-}" ]; then APP_PORT="$D"; ok "المنفذ المطلوب: ${APP_PORT}"
    else APP_PORT=7300; warn "لا طلبات في السجل — سيُستخدم 7300."; fi
fi
case "$APP_PORT" in ''|*[!0-9]*) die "منفذ غير صالح: $APP_PORT";; esac

if tcp_ok 127.0.0.1 "$APP_PORT"; then
    ok "يوجد بالفعل من يستجيب على 127.0.0.1:${APP_PORT}"
    exit 0
fi

# ==================== ٢) محاولة تحرير المنفذ ====================
BIND_RESULT=""
LISTEN_PORT="$APP_PORT"
NEED_REDIRECT=0

if ! can_bind "$APP_PORT"; then
    warn "المنفذ ${APP_PORT} محجوز: ${BIND_RESULT}"
    echo "  من يحتجزه:"
    ss -tanp 2>/dev/null | grep -E "[:.]${APP_PORT}[[:space:]]" | sed 's/^/    tcp  /' || true
    ss -uanp 2>/dev/null | grep -E "[:.]${APP_PORT}[[:space:]]" | sed 's/^/    udp  /' || true
    command -v lsof  >/dev/null 2>&1 && lsof -nP -i :"$APP_PORT" 2>/dev/null | sed 's/^/    lsof /' || true
    command -v fuser >/dev/null 2>&1 && fuser -n tcp "$APP_PORT" 2>&1 | sed 's/^/    fuser /' || true

    # قتل ما يمكن العثور عليه
    KILLED=0
    for pid in $(ss -tanp 2>/dev/null | grep -E "[:.]${APP_PORT}[[:space:]]" \
                 | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        warn "  إيقاف العملية ${pid} ($(cat /proc/"$pid"/comm 2>/dev/null || echo '?'))"
        kill "$pid" 2>/dev/null || true; KILLED=1
    done
    if command -v fuser >/dev/null 2>&1; then
        fuser -k -n tcp "$APP_PORT" >/dev/null 2>&1 && KILLED=1 || true
    fi
    [ "$KILLED" = "1" ] && sleep 2

    if can_bind "$APP_PORT"; then
        ok "تم تحرير المنفذ ${APP_PORT}"
    else
        # مقبس مرتبط بلا listen لا تراه أي أداة ولا يمكن قتله.
        # نشغّل udpgw على منفذ حر ونحوّل إليه.
        warn "تعذّر تحديد المُحتجِز — سيُستخدم التحويل بدلاً من الصراع معه."
        LISTEN_PORT=""
        for p in $(seq 7301 7399); do
            if can_bind "$p"; then LISTEN_PORT="$p"; break; fi
        done
        [ -n "$LISTEN_PORT" ] || die "لا يوجد منفذ حر في المدى 7301-7399."
        NEED_REDIRECT=1
        ok "سيعمل udpgw على ${LISTEN_PORT} مع تحويل ${APP_PORT} إليه"
    fi
fi

# ==================== ٣) الملفات التنفيذية المرشَّحة ====================
CANDIDATES=""
add_cand() { [ -x "$1" ] && case " $CANDIDATES " in *" $1 "*) : ;; *) CANDIDATES="$CANDIDATES $1";; esac; return 0; }

if [ ! -x /usr/bin/badvpn-udpgw ] && [ ! -x "$BUILD_PREFIX/bin/badvpn-udpgw" ] \
   && [ ! -x /usr/local/bin/badvpn-udpgw ]; then
    log "تركيب حزمة badvpn..."
    (DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1 \
     || (timeout 240 apt-get update >/dev/null 2>&1 \
         && DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1)) || true
fi
add_cand /usr/bin/badvpn-udpgw
add_cand "$BUILD_PREFIX/bin/badvpn-udpgw"
add_cand /usr/local/bin/badvpn-udpgw
[ -n "$CANDIDATES" ] || die "لا يوجد badvpn-udpgw. ثبّته: apt install -y badvpn"

# ==================== ٤) اختيار ملف تنفيذي يعمل ====================
WORKING_BIN=""; WORKING_ARGS=""; LAST_OUT=""
try_bin() {
    local b="$1"; shift
    local out rc=0
    out=$(timeout 3 "$b" "$@" 2>&1) || rc=$?
    LAST_OUT="$out"
    [ "$rc" -eq 124 ]
}

select_binary() {   # $1 = المنفذ المراد الاستماع عليه
    local port="$1" c
    WORKING_BIN=""; WORKING_ARGS=""
    for c in $CANDIDATES; do
        printf '      %s — ' "$c"
        if try_bin "$c" --listen-addr "127.0.0.1:${port}" \
                --max-clients "$MAX_CLIENTS" --max-connections-for-client "$MAX_CONN_PER_CLIENT"; then
            WORKING_BIN="$c"
            WORKING_ARGS="--listen-addr 127.0.0.1:${port} --max-clients ${MAX_CLIENTS} --max-connections-for-client ${MAX_CONN_PER_CLIENT}"
            echo "نجح"; return 0
        fi
        if try_bin "$c" --listen-addr "127.0.0.1:${port}"; then
            WORKING_BIN="$c"; WORKING_ARGS="--listen-addr 127.0.0.1:${port}"
            echo "نجح (معاملات مبسّطة)"; return 0
        fi
        echo "فشل"
    done
    return 1
}

log "اختبار التشغيل على المنفذ ${LISTEN_PORT}..."
if ! select_binary "$LISTEN_PORT"; then
    # قد يكون python3 غائباً فلم يُكتشف احتجاز المنفذ مبكراً.
    # نجرّب منفذاً بديلاً مع التحويل بدل الاستسلام.
    if [ "$NEED_REDIRECT" = "0" ]; then
        warn "فشل التشغيل على ${LISTEN_PORT} — تجربة منفذ بديل مع التحويل..."
        for p in $(seq 7301 7399); do
            if select_binary "$p"; then
                LISTEN_PORT="$p"; NEED_REDIRECT=1
                ok "سيعمل udpgw على ${LISTEN_PORT} مع تحويل ${APP_PORT} إليه"
                break
            fi
        done
    fi
fi

if [ -z "$WORKING_BIN" ]; then
    echo; echo "آخر خطأ:"; printf '%s\n' "$LAST_OUT" | sed 's/^/    /'
    die "تعذّر تشغيل udpgw على أي ملف تنفيذي أو منفذ."
fi
ok "الملف المعتمد: ${WORKING_BIN}"

# ==================== ٥) سكربت التحويل ====================
mkdir -p /etc/hysteria
cat > "$HELPER" <<EOF
#!/usr/bin/env bash
# تحويل اتصالات hysteria الصادرة نحو المنفذ الذي يطلبه التطبيق
set -uo pipefail
export PATH="/usr/sbin:/sbin:\$PATH"
APP_PORT=${APP_PORT}
LISTEN_PORT=${LISTEN_PORT}
NEED_REDIRECT=${NEED_REDIRECT}

iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT >/dev/null 2>&1

# إزالة أي تحويل سابق
while iptables -t nat -C OUTPUT -d 127.0.0.1/32 -p tcp --dport "\$APP_PORT" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT" >/dev/null 2>&1; do
    iptables -t nat -D OUTPUT -d 127.0.0.1/32 -p tcp --dport "\$APP_PORT" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT" >/dev/null 2>&1 || break
done

if [ "\$NEED_REDIRECT" = "1" ]; then
    iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p tcp --dport "\$APP_PORT" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT" >/dev/null 2>&1
fi
exit 0
EOF
chmod 700 "$HELPER"
bash "$HELPER" || warn "تعذّر تطبيق قاعدة التحويل."

# ==================== ٦) الخدمة ====================
log "إنشاء خدمة badvpn-udpgw..."
cat > /etc/systemd/system/badvpn-udpgw.service <<EOF
[Unit]
Description=BadVPN udpgw - UDP forwarding for VPN clients
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
ExecStartPre=/bin/bash ${HELPER}
ExecStart=${WORKING_BIN} ${WORKING_ARGS}
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

if ! systemctl is-active --quiet "$SVC"; then
    log "تشغيل خدمة hysteria..."
    systemctl reset-failed "$SVC" >/dev/null 2>&1 || true
    systemctl start "$SVC" >/dev/null 2>&1 || true
fi

# ==================== ٧) التحقق ====================
log "التحقق..."
sleep 4
FAIL=0

if systemctl is-active --quiet badvpn-udpgw.service; then
    ok "خدمة udpgw تعمل على ${LISTEN_PORT}"
else
    warn "خدمة udpgw متوقفة:"
    journalctl -u badvpn-udpgw.service -n 12 --no-pager | sed 's/^/    /' || true
    FAIL=1
fi

# الاختبار الحاسم: نفس ما يفعله hysteria بالضبط
if tcp_ok 127.0.0.1 "$APP_PORT"; then
    ok "الاتصال بـ 127.0.0.1:${APP_PORT} ناجح — هذا ما يطلبه التطبيق"
else
    warn "ما زال الاتصال بـ ${APP_PORT} فاشلاً"
    [ "$NEED_REDIRECT" = "1" ] && iptables -t nat -L OUTPUT -n -v | grep -i redirect | sed 's/^/    /' || true
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
    echo " جاهز."
    echo "   udpgw     : ${WORKING_BIN}"
    echo "   يستمع على : 127.0.0.1:${LISTEN_PORT}"
    if [ "$NEED_REDIRECT" = "1" ]; then
        echo "   التحويل   : ${APP_PORT} ← ${LISTEN_PORT} (المنفذ الأصلي محجوز)"
    fi
    echo
    echo " افتح التطبيق واتصل ثم جرّب التصفح."
    echo " للمراقبة:  journalctl -u ${SVC} -f"
    echo " يجب أن تختفي أسطر connection refused وتظهر"
    echo " وجهات حقيقية مثل  dst:142.250.x.x:443"
    echo "════════════════════════════════════════════════════"
else
    die "بقيت مشكلة — راجع المخرجات أعلاه."
fi
