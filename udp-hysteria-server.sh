#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — إصلاح التصفح: تشغيل badvpn-udpgw
#
#  السبب المؤكَّد من سجل السيرفر:
#     [dst:127.0.0.1:7300] [error:dial tcp 127.0.0.1:7300: connection refused]
#  التطبيق يمرّر كل حركة UDP — وأولها استعلامات DNS — عبر udpgw على
#  127.0.0.1:7300 داخل السيرفر. المنفذ فارغ فتُرفض كل الاستعلامات،
#  فلا يُترجم أي اسم نطاق، فلا يفتح أي موقع، بينما يبقى النفق قائماً.
#
#  الملف الموجود في /usr/local/bin/badvpn-udpgw نسخة معدّلة من لوحة SSHPLUS
#  تفشل في الارتباط بأي عنوان (فشلت مع 127.0.0.1 و 0.0.0.0 بنفس الخطأ).
#  لذلك يجرّب هذا السكربت عدة ملفات تنفيذية ويستخدم أولها نجاحاً.
#
#  الاستخدام:  sudo bash udpgw-setup.sh
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:$PATH"

UDPGW_PORT="${UDPGW_PORT:-auto}"
MAX_CLIENTS="${MAX_CLIENTS:-1000}"
MAX_CONN_PER_CLIENT="${MAX_CONN_PER_CLIENT:-10}"
SVC="hysteria-server"
BUILD_PREFIX=/opt/badvpn      # بناء منفصل حتى لا نستبدل ملف اللوحة

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "يجب تشغيل السكربت بصلاحيات root."
tcp_ok() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

# ==================== ١) المنفذ الذي يطلبه التطبيق ====================
if [ "$UDPGW_PORT" = "auto" ]; then
    log "قراءة سجل hysteria..."
    DETECTED=$(journalctl -u "$SVC" -n 5000 --no-pager 2>/dev/null \
        | grep -oE 'dst:127\.0\.0\.1:[0-9]+' \
        | grep -oE '[0-9]+$' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || true)
    if [ -n "${DETECTED:-}" ]; then
        UDPGW_PORT="$DETECTED"; ok "المنفذ المطلوب من المستخدمين: ${UDPGW_PORT}"
    else
        UDPGW_PORT=7300; warn "لا طلبات في السجل — سيُستخدم 7300."
    fi
fi
case "$UDPGW_PORT" in ''|*[!0-9]*) die "منفذ غير صالح: $UDPGW_PORT";; esac

if tcp_ok 127.0.0.1 "$UDPGW_PORT"; then
    ok "يوجد بالفعل من يستمع على 127.0.0.1:${UDPGW_PORT}"
    ss -ltnp 2>/dev/null | grep -E "[:.]${UDPGW_PORT}[[:space:]]" | sed 's/^/    /'
    exit 0
fi

# ============ ٢) هل المشكلة في النظام أم في البرنامج؟ ============
# نرتبط بالمنفذ عبر python لعزل السبب: لو نجح فالنظام سليم والعطل
# في الملف التنفيذي، وهذا يوفّر مطاردة أسباب وهمية.
log "اختبار الارتباط بالمنفذ ${UDPGW_PORT} عبر أداة مستقلة..."
if command -v python3 >/dev/null 2>&1; then
    PYRES=$(python3 - "$UDPGW_PORT" <<'PY' 2>&1 || true
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port)); s.listen(1); print("OK")
except OSError as e:
    print("FAIL errno=%d %s" % (e.errno, e.strerror))
finally:
    s.close()
PY
)
    case "$PYRES" in
        OK*) ok "النظام يسمح بالارتباط — العطل في الملف التنفيذي" ;;
        *)   warn "النظام نفسه يمنع الارتباط: ${PYRES}"
             warn "هذا سبب مختلف تماماً — أرسل لي هذا السطر." ;;
    esac
else
    warn "python3 غير موجود — تخطّي هذا الفحص"
fi

# ==================== ٣) جمع الملفات التنفيذية المرشَّحة ====================
CANDIDATES=""
add_cand() { [ -x "$1" ] && case " $CANDIDATES " in *" $1 "*) : ;; *) CANDIDATES="$CANDIDATES $1";; esac; return 0; }

# الرسمي من المستودعات أولاً — النسخة المعدّلة في /usr/local آخراً
if [ ! -x /usr/bin/badvpn-udpgw ]; then
    log "تركيب حزمة badvpn الرسمية..."
    (DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1 \
     || (timeout 240 apt-get update >/dev/null 2>&1 \
         && DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1) \
     || (timeout 120 apt-get install -y software-properties-common >/dev/null 2>&1 \
         && add-apt-repository -y universe >/dev/null 2>&1 \
         && timeout 240 apt-get update >/dev/null 2>&1 \
         && DEBIAN_FRONTEND=noninteractive timeout 180 apt-get install -y badvpn >/dev/null 2>&1)) || true
fi
add_cand /usr/bin/badvpn-udpgw
add_cand "$BUILD_PREFIX/bin/badvpn-udpgw"
add_cand /usr/local/bin/badvpn-udpgw

# ==================== ٤) اختبار كل مرشَّح ====================
WORKING_BIN=""; WORKING_ARGS=""; LAST_OUT=""
try_bin() {
    local bin="$1"; shift
    local out rc=0
    out=$(timeout 3 "$bin" "$@" 2>&1) || rc=$?
    LAST_OUT="$out"
    [ "$rc" -eq 124 ]
}

test_candidate() {
    local bin="$1" ver
    ver=$("$bin" --version 2>&1 | head -1 || true)
    log "اختبار ${bin}"
    [ -n "$ver" ] && printf '      %s\n' "$ver"

    if try_bin "$bin" --listen-addr "127.0.0.1:${UDPGW_PORT}" \
            --max-clients "$MAX_CLIENTS" --max-connections-for-client "$MAX_CONN_PER_CLIENT"; then
        WORKING_BIN="$bin"
        WORKING_ARGS="--listen-addr 127.0.0.1:${UDPGW_PORT} --max-clients ${MAX_CLIENTS} --max-connections-for-client ${MAX_CONN_PER_CLIENT}"
        return 0
    fi
    if try_bin "$bin" --listen-addr "127.0.0.1:${UDPGW_PORT}"; then
        WORKING_BIN="$bin"
        WORKING_ARGS="--listen-addr 127.0.0.1:${UDPGW_PORT}"
        return 0
    fi
    printf '      فشل: %s\n' "$(printf '%s' "$LAST_OUT" | tr '\n' ' ' | cut -c1-110)"
    return 1
}

for c in $CANDIDATES; do
    if test_candidate "$c"; then ok "نجح: ${WORKING_BIN}"; break; fi
done

# ==================== ٥) البناء من المصدر عند الحاجة ====================
if [ -z "$WORKING_BIN" ]; then
    log "لم ينجح أي ملف موجود — بناء نسخة نظيفة من المصدر..."
    (DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y \
        cmake make gcc git >/dev/null 2>&1) || true
    B=$(mktemp -d /tmp/badvpn.XXXXXX)
    if timeout 240 git clone --depth 1 https://github.com/ambrop72/badvpn.git "$B/src" >/dev/null 2>&1; then
        mkdir -p "$B/b"
        if (cd "$B/b" && cmake ../src -DCMAKE_INSTALL_PREFIX="$BUILD_PREFIX" \
                -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1 \
            && make >/dev/null 2>&1 && make install >/dev/null 2>&1); then
            ok "تم البناء في ${BUILD_PREFIX}/bin/badvpn-udpgw"
            if test_candidate "$BUILD_PREFIX/bin/badvpn-udpgw"; then
                ok "نجح: ${WORKING_BIN}"
            fi
        else
            warn "فشل البناء"
        fi
    else
        warn "تعذّر تنزيل المصدر"
    fi
    rm -rf "$B"
fi

if [ -z "$WORKING_BIN" ]; then
    echo
    echo "آخر خطأ:"; printf '%s\n' "$LAST_OUT" | sed 's/^/    /'
    echo "الملفات التي جُرّبت:"; for c in $CANDIDATES; do echo "    $c"; done
    echo "المنفذ ${UDPGW_PORT}:"; ss -ltnp 2>/dev/null | grep -E "[:.]${UDPGW_PORT}[[:space:]]" | sed 's/^/    /' || echo "    (فارغ)"
    die "تعذّر تشغيل udpgw."
fi

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

iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT 1 -i lo -j ACCEPT >/dev/null 2>&1

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
    echo " جاهز.  udpgw: ${WORKING_BIN}"
    echo " افتح التطبيق واتصل ثم جرّب التصفح."
    echo
    echo " للمراقبة:  journalctl -u ${SVC} -f"
    echo " يجب أن تختفي أسطر connection refused وتظهر"
    echo " وجهات حقيقية مثل  dst:142.250.x.x:443"
    echo "════════════════════════════════════════════════════"
else
    die "بقيت مشكلة — راجع المخرجات أعلاه."
fi
