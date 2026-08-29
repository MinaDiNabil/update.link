#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — Hysteria v1 UDP Server  (نسخة مُصلَّحة ومُحسَّنة)
#
#  ★ إصلاح مشكلة "يتصل لكن لا يتصفح" ★
#  التصفح يجري من السيرفر نفسه: hysteria هو من يفتح الاتصال بجوجل نيابةً عن
#  المستخدم. لذلك لا يكفي أن ينجح الاتصال — يجب اختبار مسار الوكيل كاملاً.
#  هذا الإصدار يشغّل عميل hysteria على السيرفر ويتصفح فعلياً عبر النفق،
#  ويميّز بدقة بين ثلاث حالات:
#     • فشل ترجمة الأسماء داخل السيرفر (DNS)
#     • فشل خروج السيرفر إلى الإنترنت
#     • السيرفر سليم والمشكلة في مسار القفز أو في التطبيق
#
#  كما أُزيل مصدران للأعطال أضفتُهما ولم يكونا في إعدادك الأصلي:
#     • resolver ثابت — عاد إلى DNS النظام إلا إذا ثبت عجزه
#     • IPv6 — يُفرض IPv4 افتراضياً لأن جوجل ويوتيوب مزدوجة المكدس
#
#  الاستخدام:
#    sudo PASSWORDS="2a1d4b9896e:7823f72fcd10:16fbcee5gf" bash udp-hysteria-server.sh
#  اختبار التصفح لاحقاً:  hy-test        تشخيص شامل:  hy-doctor
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

# ----------------------------------------------------------------- الإعدادات
LISTEN_PORT="${LISTEN_PORT:-36712}"   # منفذ داخلي — العملاء يتصلون عبر نطاق القفز
ENABLE_HOP="${ENABLE_HOP:-1}"
HOP_START="${HOP_START:-1}"
HOP_END="${HOP_END:-65535}"

UP_MBPS="${UP_MBPS:-100}"             # الحد الأقصى لكل عميل — يطابق 100:100
DOWN_MBPS="${DOWN_MBPS:-100}"

OBFS_PASS="${OBFS_PASS:-minapronet}"
ENABLE_OBFS="${ENABLE_OBFS:-1}"
ALPN="${ALPN:-}"
RESOLVER="${RESOLVER:-auto}"          # auto = DNS النظام، وبديل عام إن فشل
USE_IPV6="${USE_IPV6:-0}"             # 0 = IPv4 فقط (الأكثر أماناً للتصفح)
MAX_CONN_CLIENT="${MAX_CONN_CLIENT:-4096}"
DISABLE_MTU_DISC="${DISABLE_MTU_DISC:-true}"
LOG_LEVEL="${LOG_LEVEL:-info}"
ENABLE_BBR="${ENABLE_BBR:-1}"
SNI="${SNI:-www.bing.com}"
HY_DIR="/etc/hysteria"
HY_BIN="${HY_BIN:-/usr/local/bin/hysteria}"
SVC="hysteria-server"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-multiuser.conf"

EPH_START=30000
EPH_END=65000

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

jq_() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
tcp_probe() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }
port_busy() { ss -lun 2>/dev/null | grep -qE "[:*.]${1}[[:space:]]"; }
port_pids() {
    ss -lunp 2>/dev/null | grep -E "[:*.]${1}[[:space:]]" \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true
}

if [ "$(id -u)" -ne 0 ]; then die "يجب تشغيل السكربت بصلاحيات root."; fi
for t in iptables openssl timeout ss; do
    command -v "$t" >/dev/null 2>&1 || die "$t غير مثبت."
done
if [ ! -x "$HY_BIN" ]; then die "ملف hysteria التنفيذي غير موجود في $HY_BIN"; fi

HY_VER_RAW="$("$HY_BIN" version 2>/dev/null || "$HY_BIN" --version 2>/dev/null || "$HY_BIN" -v 2>/dev/null || echo '')"
if printf '%s' "$HY_VER_RAW" | grep -qiE '\bv?2\.[0-9]+\.[0-9]+'; then
    die "الملف التنفيذي في $HY_BIN هو Hysteria 2 وليس v1."
fi
log "إصدار hysteria: ${HY_VER_RAW:-غير معروف}"

# ------------------------------------------------- كشف الموارد والواجهة
RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
if [ -z "${IFACE:-}" ]; then IFACE=$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}'); fi
[ -n "${IFACE:-}" ] || die "تعذّر تحديد واجهة الشبكة الخارجية."
PUBIP=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1 || true)
log "الموارد: ذاكرة ${RAM_MB}MB | واجهة ${IFACE} | IP ${PUBIP:-غير معروف}"

mkdir -p "$HY_DIR"

# ============ تحرير منفذ الاستماع ============
log "التحقق من توفّر المنفذ ${LISTEN_PORT}..."
systemctl stop "$SVC" >/dev/null 2>&1 || true
sleep 1

release_port() {
    local port="$1" pid comm unit pids
    pids=$(port_pids "$port")
    [ -z "$pids" ] && return 0
    for pid in $pids; do
        comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo '?')
        unit=$(sed -n 's|.*/system\.slice/\([^/]*\.service\).*|\1|p' /proc/"$pid"/cgroup 2>/dev/null | head -1)
        warn "المنفذ ${port} محجوز من العملية ${pid} (${comm})${unit:+ ضمن ${unit}}"
        if [ -n "${unit:-}" ] && [ "$unit" != "${SVC}.service" ]; then
            systemctl stop "$unit" >/dev/null 2>&1 || true
            systemctl disable "$unit" >/dev/null 2>&1 || true
            warn "أُوقفت الوحدة المتعارضة ${unit}"
        fi
        kill "$pid" 2>/dev/null || true
    done
    sleep 2
    for pid in $(port_pids "$port"); do kill -9 "$pid" 2>/dev/null || true; done
    sleep 1
    if port_busy "$port"; then return 1; fi
    return 0
}

if port_busy "$LISTEN_PORT"; then
    if release_port "$LISTEN_PORT"; then
        ok "تم تحرير المنفذ ${LISTEN_PORT}"
    else
        NEWP=""
        for _ in $(seq 1 60); do
            CAND=$(( (RANDOM % 9000) + 20000 ))
            if ! port_busy "$CAND"; then NEWP="$CAND"; break; fi
        done
        [ -n "$NEWP" ] || die "تعذّر إيجاد منفذ حر."
        warn "تعذّر تحرير ${LISTEN_PORT} — تم التحويل إلى ${NEWP}"
        LISTEN_PORT="$NEWP"
    fi
else
    ok "المنفذ ${LISTEN_PORT} متاح"
fi

# ============ طريقة معالجة تصادم NAT عند القفز ============
# 0 = تضييق النطاق + مهلة قصيرة شاملة | 1 = nfct | 2 = nftables
HOP_CT_MODE=0
if [ "$ENABLE_HOP" = "1" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    if ! command -v nfct >/dev/null 2>&1; then
        log "محاولة تثبيت conntrack-tools..."
        (DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y conntrack >/dev/null 2>&1 \
         || (timeout 180 apt-get update >/dev/null 2>&1 \
             && DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y conntrack >/dev/null 2>&1) \
         || timeout 120 yum install -y conntrack-tools >/dev/null 2>&1) || true
        hash -r 2>/dev/null || true
    fi
    if command -v nfct >/dev/null 2>&1 && nfct timeout list >/dev/null 2>&1; then
        HOP_CT_MODE=1
    elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        nft delete table ip hytest >/dev/null 2>&1 || true
        if nft -f - >/dev/null 2>&1 <<NFTTEST
table ip hytest {
    ct timeout short {
        protocol udp;
        l3proto ip;
        policy = { unreplied: 5, replied: 8 }
    }
    chain raw_pre {
        type filter hook prerouting priority -300; policy accept;
        iifname "${IFACE}" udp dport 1-65535 ct timeout set "short"
    }
}
NFTTEST
        then
            if nft list table ip hytest >/dev/null 2>&1; then HOP_CT_MODE=2; fi
        fi
        nft delete table ip hytest >/dev/null 2>&1 || true
    fi
fi

apply_hop_mode() {
    if [ "$ENABLE_HOP" != "1" ]; then
        CT_UDP_TIMEOUT=60; CT_UDP_STREAM=180
    elif [ "$HOP_CT_MODE" = "1" ] || [ "$HOP_CT_MODE" = "2" ]; then
        CT_UDP_TIMEOUT=60; CT_UDP_STREAM=180
    else
        if [ "$HOP_END" -ge "$EPH_START" ]; then HOP_END=$(( EPH_START - 1 )); fi
        CT_UDP_TIMEOUT=5; CT_UDP_STREAM=15
    fi
}
apply_hop_mode

case "$HOP_CT_MODE" in
    1) ok "تصادم NAT: nfct — نطاق القفز ${HOP_START}-${HOP_END}" ;;
    2) ok "تصادم NAT: nftables — نطاق القفز ${HOP_START}-${HOP_END}" ;;
    *) [ "$ENABLE_HOP" = "1" ] && warn "تصادم NAT: الوضع البديل — نطاق ${HOP_START}-${HOP_END}" ;;
esac

# ============ مسار الإنترنت: IPv4 افتراضياً ============
# جوجل ويوتيوب مزدوجة المكدس. لو كان IPv6 على السيرفر ناقصاً أو بمشكلة MTU
# فستتعلق صفحاتها بلا رسالة خطأ بينما تعمل المواقع الأخرى. الاختبار البسيط
# لا يكشف ذلك، لذا الافتراضي IPv4 فقط ولا يُفعّل IPv6 إلا بطلب صريح.
if [ "$USE_IPV6" = "1" ]; then
    RESOLVE_PREF="46"; warn "IPv6 مفعّل بطلبك — إن تعطّل التصفح أعد التشغيل بلا USE_IPV6."
else
    RESOLVE_PREF="4"; log "مسار الإنترنت: IPv4 فقط"
fi

# ============ DNS: نستخدم DNS النظام إلا إذا عجز ============
log "اختبار ترجمة الأسماء على السيرفر..."
if getent ahostsv4 www.google.com >/dev/null 2>&1; then
    if [ "$RESOLVER" = "auto" ]; then RESOLVER=""; fi
    ok "DNS النظام يعمل — لن يُفرض خادم DNS خارجي"
else
    warn "DNS النظام لا يترجم الأسماء — البحث عن بديل..."
    if [ "$RESOLVER" = "auto" ]; then
        RESOLVER=""
        for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
            if tcp_probe "$r" 53; then RESOLVER="udp://${r}:53"; break; fi
        done
    fi
    [ -n "$RESOLVER" ] && ok "خادم DNS البديل: ${RESOLVER}" || warn "لم يُعثر على بديل!"
fi

if tcp_probe 1.1.1.1 443; then ok "خروج IPv4 من السيرفر يعمل"; else warn "تعذّر الخروج إلى 1.1.1.1:443"; fi

# نوافذ QUIC (افتراضي v1: 15MB و64MB لكل عميل)
if [ "$RAM_MB" -le 1200 ]; then
    RECV_CONN=8388608;  RECV_CLIENT=33554432
else
    RECV_CONN=15728640; RECV_CLIENT=67108864
fi

CT_MAX=$(( RAM_MB * 256 ))
if [ "$CT_MAX" -gt 1048576 ]; then CT_MAX=1048576; fi
if [ "$CT_MAX" -lt 262144 ];  then CT_MAX=262144;  fi
CT_BUCKETS=$(( CT_MAX / 4 ))

read -r UM_MIN UM_PRESS UM_MAX < /proc/sys/net/ipv4/udp_mem 2>/dev/null || { UM_MIN=0; UM_PRESS=0; UM_MAX=0; }
UDP_MEM_MAX=$(( RAM_MB * 256 / 4 ))
[ "$UDP_MEM_MAX" -lt "$UM_MAX" ] && UDP_MEM_MAX="$UM_MAX"
UDP_MEM_PRESS=$(( UDP_MEM_MAX * 3 / 4 ))
[ "$UDP_MEM_PRESS" -lt "$UM_PRESS" ] && UDP_MEM_PRESS="$UM_PRESS"
UDP_MEM_MIN=$(( UDP_MEM_MAX / 4 ))
[ "$UDP_MEM_MIN" -lt "$UM_MIN" ] && UDP_MEM_MIN="$UM_MIN"

# ------------------------------------ الحفاظ على كلمة المرور الحالية
OLD_PASS=""
if [ -f "$HY_DIR/config.json" ]; then
    OLD_PASS=$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$HY_DIR/config.json" 2>/dev/null \
        | head -1 | sed 's/.*"password"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)
    if [ -z "$OLD_PASS" ]; then
        OLD_PASS=$(sed -n '/"auth"/,/}/p' "$HY_DIR/config.json" 2>/dev/null \
            | grep -o '"[^"]\{4,\}"' \
            | grep -vE '^"(auth|mode|config|password|passwords|external|none)"$' \
            | head -1 | tr -d '"' || true)
    fi
fi
if [ -z "$OLD_PASS" ]; then
    LAST_BAK=$(ls -1t "$HY_DIR"/config.json.bak.* 2>/dev/null | head -1 || true)
    if [ -n "${LAST_BAK:-}" ]; then
        OLD_PASS=$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$LAST_BAK" 2>/dev/null \
            | head -1 | sed 's/.*"password"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)
    fi
fi
PASSWORDS="${PASSWORDS:-${OLD_PASS:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)}}"
FIRST_PASS="${PASSWORDS%%,*}"

# ========================================================= 1) إعدادات النواة
write_sysctl() {
cat > "$SYSCTL_FILE" <<EOF
# ===== Hysteria v1 / QUIC tuning — MinaProNet =====

# --- حجز منفذ الاستماع لئلا تخطفه عملية أخرى كمنفذ مصدر مؤقت ---
net.ipv4.ip_local_reserved_ports = ${LISTEN_PORT}

# --- مهلة تتبّع UDP ---
net.netfilter.nf_conntrack_udp_timeout = ${CT_UDP_TIMEOUT}
net.netfilter.nf_conntrack_udp_timeout_stream = ${CT_UDP_STREAM}
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# --- سقف مخازن المقابس (سقف لا تخصيص) ---
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 16384

# --- ذاكرة UDP للنظام (بالصفحات) — أعلى من افتراضي النواة دائماً ---
net.ipv4.udp_mem = ${UDP_MEM_MIN} ${UDP_MEM_PRESS} ${UDP_MEM_MAX}
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- منافذ السيرفر الصادرة ---
net.ipv4.ip_local_port_range = ${EPH_START} ${EPH_END}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_max_tw_buckets = 262144
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

fs.file-max = 2097152
fs.nr_open = 2097152
net.ipv4.ip_forward = 1
EOF
if [ "$ENABLE_BBR" = "1" ] && modprobe tcp_bbr 2>/dev/null; then
    printf '\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' >> "$SYSCTL_FILE"
fi
sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

log "كتابة إعدادات النواة..."
modprobe nf_conntrack 2>/dev/null || true
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi
write_sysctl
ok "إعدادات النواة مطبَّقة (المنفذ ${LISTEN_PORT} محجوز | udp_timeout=${CT_UDP_TIMEOUT}s)"

cat > /etc/security/limits.d/99-hysteria.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

# ==================================================== 2) المستخدم والشهادة
if ! id -u hysteria >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin hysteria
    log "أُنشئ مستخدم الخدمة hysteria"
fi
if [ ! -s "$HY_DIR/server.crt" ] || [ ! -s "$HY_DIR/server.key" ]; then
    log "توليد شهادة ذاتية التوقيع..."
    openssl ecparam -name prime256v1 -out "$HY_DIR/ec.pem" >/dev/null 2>&1
    openssl req -x509 -nodes -newkey "ec:$HY_DIR/ec.pem" \
        -keyout "$HY_DIR/server.key" -out "$HY_DIR/server.crt" \
        -subj "/CN=${SNI}" -days 3650 >/dev/null 2>&1 || die "فشل توليد الشهادة."
    rm -f "$HY_DIR/ec.pem"
fi
chown root:hysteria "$HY_DIR" "$HY_DIR/server.key" "$HY_DIR/server.crt"
chmod 750 "$HY_DIR"; chmod 640 "$HY_DIR/server.key"; chmod 644 "$HY_DIR/server.crt"

# ======================================================= 3) ملف الإعداد
pw_array() {
    local out="" p old_ifs="$IFS"
    IFS=','
    for p in $PASSWORDS; do
        [ -z "$p" ] && continue
        if [ -n "$out" ]; then out="$out, "; fi
        out="${out}$(jq_ "$p")"
    done
    IFS="$old_ifs"
    printf '[%s]' "$out"
}

build_config() {
    local style="$1" path="$2" auth_block obfs_line="" alpn_line="" res_line=""
    if [ "$style" = "array" ]; then
        auth_block="\"auth\": { \"mode\": \"passwords\", \"config\": $(pw_array) },"
    else
        auth_block="\"auth\": { \"mode\": \"password\", \"config\": { \"password\": $(jq_ "$FIRST_PASS") } },"
    fi
    if [ "$ENABLE_OBFS" = "1" ]; then obfs_line="    \"obfs\": $(jq_ "$OBFS_PASS"),"; fi
    if [ -n "$ALPN" ];            then alpn_line="    \"alpn\": $(jq_ "$ALPN"),";     fi
    if [ -n "$RESOLVER" ];        then res_line="    \"resolver\": $(jq_ "$RESOLVER"),"; fi

    cat > "$path" <<EOF
{
    "listen": ":${LISTEN_PORT}",
    "protocol": "udp",
    "cert": "${HY_DIR}/server.crt",
    "key": "${HY_DIR}/server.key",
${obfs_line}
${alpn_line}
    ${auth_block}
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS},
    "disable_udp": false,
    "recv_window_conn": ${RECV_CONN},
    "recv_window_client": ${RECV_CLIENT},
    "max_conn_client": ${MAX_CONN_CLIENT},
    "disable_mtu_discovery": ${DISABLE_MTU_DISC},
${res_line}
    "resolve_preference": "${RESOLVE_PREF}"
}
EOF
    sed -i '/^[[:space:]]*$/d' "$path"
}

PROBE_OUT=""
probe_auth_style() {
    local style="$1" tmp probe_port out rc save_port
    tmp="$(mktemp /tmp/hy-probe.XXXXXX.json)"
    probe_port=$(( (RANDOM % 3000) + 46000 ))
    while port_busy "$probe_port"; do probe_port=$(( probe_port + 1 )); done
    save_port="$LISTEN_PORT"; LISTEN_PORT="$probe_port"
    build_config "$style" "$tmp"
    LISTEN_PORT="$save_port"
    rc=0
    out=$(timeout 4 "$HY_BIN" server --config "$tmp" 2>&1) || rc=$?
    rm -f "$tmp"; PROBE_OUT="$out"
    [ "$rc" -eq 124 ]
}

log "اختبار صيغة المصادقة المدعومة..."
AUTH_STYLE=""
if probe_auth_style "array"; then
    AUTH_STYLE="array"; ok "الصيغة المدعومة: mode=passwords"
elif probe_auth_style "object"; then
    AUTH_STYLE="object"; warn "إصدار قديم: mode=password"
else
    echo "$PROBE_OUT" | tail -20
    die "فشل تشغيل hysteria بأي من الصيغتين."
fi

STAMP=$(date +%s)
if [ -f "$HY_DIR/config.json" ]; then cp -a "$HY_DIR/config.json" "$HY_DIR/config.json.bak.$STAMP"; fi
build_config "$AUTH_STYLE" "$HY_DIR/config.json"
chown root:hysteria "$HY_DIR/config.json"; chmod 640 "$HY_DIR/config.json"
ok "تم إنشاء $HY_DIR/config.json"

# ====================================================== 4) الجدار الناري
write_firewall() {
cat > "$HY_DIR/firewall.sh" <<EOFW
#!/usr/bin/env bash
set -uo pipefail
export PATH="/usr/sbin:/sbin:\$PATH"
LISTEN_PORT="${LISTEN_PORT}"
HOP_START="${HOP_START}"
HOP_END="${HOP_END}"
ENABLE_HOP="${ENABLE_HOP}"
HOP_CT_MODE="${HOP_CT_MODE}"
IFACE="${IFACE}"

# --- حذف القواعد القديمة المكتوبة مباشرة في PREROUTING ---
while read -r spec; do
    [ -z "\$spec" ] && continue
    # shellcheck disable=SC2086
    iptables -t nat -D PREROUTING \${spec#-A PREROUTING } >/dev/null 2>&1 || true
done < <(iptables-save -t nat 2>/dev/null | grep -E '^-A PREROUTING .*REDIRECT.*(dport|dports) (1:65535|1-65535)' || true)

while iptables -C INPUT -p udp -j ACCEPT >/dev/null 2>&1; do
    iptables -D INPUT -p udp -j ACCEPT >/dev/null 2>&1 || break
done

# ============ مهلة قصيرة لحركة القفز وحدها (إصلاح Connection Lost) ============
iptables -t raw -N HY_RAW >/dev/null 2>&1 || true
iptables -t raw -F HY_RAW >/dev/null 2>&1
iptables -t raw -C PREROUTING -j HY_RAW >/dev/null 2>&1 || iptables -t raw -I PREROUTING 1 -j HY_RAW >/dev/null 2>&1
nft delete table ip hyhop >/dev/null 2>&1 || true

if [ "\$ENABLE_HOP" = "1" ] && [ "\$HOP_CT_MODE" = "1" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    nfct timeout delete hyhop >/dev/null 2>&1 || true
    nfct timeout add hyhop inet udp unreplied 5 replied 8 >/dev/null 2>&1 || true
    iptables -t raw -A HY_RAW -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j CT --timeout hyhop >/dev/null 2>&1 || echo "تحذير: فشل تطبيق مهلة القفز (nfct)" >&2
elif [ "\$ENABLE_HOP" = "1" ] && [ "\$HOP_CT_MODE" = "2" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    nft -f - >/dev/null 2>&1 <<NFT || echo "تحذير: فشل تطبيق مهلة القفز (nft)" >&2
table ip hyhop {
    ct timeout short {
        protocol udp;
        l3proto ip;
        policy = { unreplied: 5, replied: 8 }
    }
    chain raw_pre {
        type filter hook prerouting priority -300; policy accept;
        iifname "\$IFACE" udp dport \$HOP_START-\$HOP_END ct timeout set "short"
    }
}
NFT
fi

# ============================ قفز المنافذ ============================
iptables -t nat -N HY_HOP >/dev/null 2>&1 || true
iptables -t nat -F HY_HOP >/dev/null 2>&1
iptables -t nat -C PREROUTING -j HY_HOP >/dev/null 2>&1 || iptables -t nat -I PREROUTING 1 -j HY_HOP >/dev/null 2>&1

if [ "\$ENABLE_HOP" = "1" ]; then
    # استثناءات إجبارية: DHCP ومنافذ الخدمات الأخرى + منافذ السيرفر الصادرة.
    # استثناء المنافذ الصادرة يضمن ألا تُخطف ردود DNS وحركة الوكيل أبداً،
    # وهو ما يحمي التصفح حتى لو انتهى عمر سجل الاتصال.
    EXCLUDE="67 68 546 547"
    OTHERS=\$(ss -lun 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if(\$i ~ /:[0-9]+\$/){sub(/.*:/,"",\$i); print \$i; break}}' \\
             | grep -E '^[0-9]+\$' | sort -un || true)
    EXCLUDE="\$EXCLUDE \$OTHERS"
    for p in \$EXCLUDE; do
        case "\$p" in ''|*[!0-9]*) continue;; esac
        [ "\$p" = "\$LISTEN_PORT" ] && continue
        [ "\$p" -lt "\$HOP_START" ] && continue
        [ "\$p" -gt "\$HOP_END" ] && continue
        iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$p" -j RETURN >/dev/null 2>&1
    done
    # حركة العودة لاتصالات السيرفر الصادرة لا تُعاد توجيهها إطلاقاً
    iptables -t nat -A HY_HOP -i "\$IFACE" -p udp -m conntrack --ctstate ESTABLISHED,RELATED \\
        -j RETURN >/dev/null 2>&1 || true

    iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT" >/dev/null 2>&1
fi

# ============================ السماح في INPUT ============================
iptables -N HY_IN >/dev/null 2>&1 || true
iptables -F HY_IN >/dev/null 2>&1
iptables -C INPUT -j HY_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j HY_IN >/dev/null 2>&1
iptables -A HY_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 \\
    || iptables -A HY_IN -m state --state ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
iptables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT >/dev/null 2>&1
iptables -A HY_IN -i lo -j ACCEPT >/dev/null 2>&1

# ============================ IPv6 ============================
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY_IN >/dev/null 2>&1 || true
    ip6tables -F HY_IN >/dev/null 2>&1 || true
    ip6tables -C INPUT -j HY_IN >/dev/null 2>&1 || ip6tables -I INPUT 1 -j HY_IN >/dev/null 2>&1 || true
    ip6tables -A HY_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT >/dev/null 2>&1 || true
fi

exit 0
EOFW
chown root:root "$HY_DIR/firewall.sh"
chmod 700 "$HY_DIR/firewall.sh"
}

verify_hop_ct() {
    case "$HOP_CT_MODE" in
        1) iptables -t raw -S HY_RAW 2>/dev/null | grep -q 'CT --timeout' ;;
        2) nft list table ip hyhop >/dev/null 2>&1 ;;
        *) return 0 ;;
    esac
}

log "إعادة بناء قواعد الجدار الناري..."
write_firewall
bash "$HY_DIR/firewall.sh" || warn "بعض قواعد الجدار الناري لم تُطبَّق."
if ! verify_hop_ct; then
    warn "فشل تطبيق مهلة القفز — انتقال تلقائي للوضع البديل."
    HOP_CT_MODE=0; apply_hop_mode; write_sysctl; write_firewall
    bash "$HY_DIR/firewall.sh" || true
    warn "ضُيِّق نطاق القفز إلى ${HOP_START}-${HOP_END} — حدّثه في التطبيق."
fi
ok "قفز المنافذ: ${HOP_START}-${HOP_END} ← ${LISTEN_PORT} على ${IFACE}"

cat > /etc/systemd/system/hysteria-firewall.service <<EOF
[Unit]
Description=Hysteria firewall rules
After=network-online.target
Wants=network-online.target
Before=${SVC}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash ${HY_DIR}/firewall.sh

[Install]
WantedBy=multi-user.target
EOF

# ====================================================== 5) خدمة systemd
cat > "$HY_DIR/wait-port.sh" <<EOF
#!/usr/bin/env bash
for i in \$(seq 1 10); do
    ss -lun 2>/dev/null | grep -qE "[:*.]${LISTEN_PORT}[[:space:]]" || exit 0
    sleep 1
done
exit 0
EOF
chown root:hysteria "$HY_DIR/wait-port.sh"; chmod 750 "$HY_DIR/wait-port.sh"

log "تحديث وحدة systemd..."
cat > "/etc/systemd/system/${SVC}.service" <<EOF
[Unit]
Description=Hysteria v1 UDP Server (MinaProNet)
After=network-online.target hysteria-firewall.service
Wants=network-online.target hysteria-firewall.service
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=hysteria
Group=hysteria
WorkingDirectory=${HY_DIR}
Environment=LOGGING_LEVEL=${LOG_LEVEL}
ExecStartPre=/bin/bash ${HY_DIR}/wait-port.sh
ExecStart=${HY_BIN} server --config ${HY_DIR}/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitNPROC=65535
LimitCORE=0
TasksMax=infinity
OOMScoreAdjust=-500
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl reset-failed "$SVC" >/dev/null 2>&1 || true
systemctl enable hysteria-firewall.service >/dev/null 2>&1 || true
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC" || true

# ============ 6) اختبار التصفح الحقيقي عبر النفق ============
# نشغّل عميل hysteria على السيرفر ونتصفح فعلاً عبره. هذا يختبر نفس المسار
# الذي يسلكه المستخدم: المصادقة ثم فتح الاتصال بجوجل من داخل السيرفر.
cat > /usr/local/bin/hy-test <<EOFT
#!/usr/bin/env bash
# اختبار التصفح من طرف إلى طرف عبر نفق hysteria
export PATH="/usr/sbin:/sbin:\$PATH"
HY_BIN="${HY_BIN}"
PORT="${LISTEN_PORT}"
OBFS="${OBFS_PASS}"
AUTH="${FIRST_PASS}"
UP="${UP_MBPS}"; DOWN="${DOWN_MBPS}"
ENABLE_OBFS="${ENABLE_OBFS}"

command -v curl >/dev/null 2>&1 || { echo "curl غير مثبت: apt install -y curl"; exit 2; }

SOCKS=11080
while ss -ltn 2>/dev/null | grep -qE "[:*.]\$SOCKS[[:space:]]"; do SOCKS=\$((SOCKS+1)); done
CFG=\$(mktemp /tmp/hy-client.XXXXXX.json)
LOGF=\$(mktemp /tmp/hy-client.XXXXXX.log)
OBFSLINE=""
[ "\$ENABLE_OBFS" = "1" ] && OBFSLINE="\"obfs\": \"\$OBFS\","
cat > "\$CFG" <<CFGEOF
{
    "server": "127.0.0.1:\$PORT",
    "protocol": "udp",
    \$OBFSLINE
    "auth_str": "\$AUTH",
    "up_mbps": \$UP,
    "down_mbps": \$DOWN,
    "insecure": true,
    "socks5": { "listen": "127.0.0.1:\$SOCKS" }
}
CFGEOF

"\$HY_BIN" client --config "\$CFG" >"\$LOGF" 2>&1 &
CPID=\$!
trap 'kill \$CPID 2>/dev/null; rm -f "\$CFG" "\$LOGF"' EXIT

for i in \$(seq 1 15); do
    ss -ltn 2>/dev/null | grep -qE "[:*.]\$SOCKS[[:space:]]" && break
    sleep 1
done
if ! ss -ltn 2>/dev/null | grep -qE "[:*.]\$SOCKS[[:space:]]"; then
    echo "✗ العميل لم يتصل بالسيرفر إطلاقاً. سجل العميل:"
    tail -15 "\$LOGF"
    exit 1
fi
echo "✓ النفق قائم والمصادقة ناجحة"
echo

# الوكيل يترجم الاسم (يختبر DNS داخل السيرفر)
R1=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \\
      --socks5-hostname 127.0.0.1:\$SOCKS https://www.google.com 2>/dev/null || echo 000)
# curl يترجم محلياً ويمرر الـ IP (يختبر خروج السيرفر فقط)
R2=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \\
      --socks5 127.0.0.1:\$SOCKS https://www.google.com 2>/dev/null || echo 000)
R3=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 \\
      --socks5-hostname 127.0.0.1:\$SOCKS https://www.youtube.com 2>/dev/null || echo 000)

printf '%-46s %s\n' "google.com (الترجمة داخل السيرفر):" "\$R1"
printf '%-46s %s\n' "google.com (الترجمة محلياً):" "\$R2"
printf '%-46s %s\n' "youtube.com:" "\$R3"
echo
if [ "\$R1" != "000" ] && [ "\$R3" != "000" ]; then
    echo "✓ التصفح عبر النفق يعمل. السيرفر سليم تماماً."
    echo "  إن كان التطبيق لا يتصفح فالمشكلة في مسار القفز أو في التطبيق:"
    echo "  تأكد أن UDP Port في التطبيق يطابق النطاق المعروض في hy-status."
elif [ "\$R2" != "000" ] && [ "\$R1" = "000" ]; then
    echo "✗ خروج السيرفر سليم لكن ترجمة الأسماء داخله فاشلة."
    echo "  الحل: أعد التشغيل بـ  sudo RESOLVER=\"udp://8.8.8.8:53\" bash udp-hysteria-server.sh"
else
    echo "✗ السيرفر لا يستطيع الوصول إلى الإنترنت نيابةً عن المستخدمين."
    echo "  أسباب محتملة: حجب من مزوّد الخدمة، أو IPv6 معطوب، أو DNS."
    echo "  سجل العميل:"
    tail -15 "\$LOGF"
fi
EOFT
chmod +x /usr/local/bin/hy-test

cat > /usr/local/bin/hy-status <<EOF
#!/usr/bin/env bash
export PATH="/usr/sbin:/sbin:\$PATH"
echo "== حالة الخدمة =="
systemctl --no-pager -l status ${SVC} | head -10
echo; echo "== منفذ الاستماع =="
ss -lunp 2>/dev/null | grep -E "[:*.]${LISTEN_PORT}[[:space:]]" || echo "!! لا استماع على ${LISTEN_PORT}"
echo; echo "== نطاق القفز المطبَّق (اضبط التطبيق عليه) =="
iptables -t nat -S HY_HOP 2>/dev/null | grep REDIRECT
echo; echo "== عدّادات القفز =="
iptables -t nat -L HY_HOP -n -v 2>/dev/null | tail -n +3
echo; echo "== conntrack =="
echo "\$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) / \$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
echo; echo "== آخر 20 سطر من السجل =="
journalctl -u ${SVC} -n 20 --no-pager
EOF
chmod +x /usr/local/bin/hy-status

cat > /usr/local/bin/hy-doctor <<'EOFD'
#!/usr/bin/env bash
export PATH="/usr/sbin:/sbin:$PATH"
P() { printf '%-44s %s\n' "$1" "$2"; }
T() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 && echo "نعم" || echo "لا"; }
PORT=$(grep -oE '"listen":[[:space:]]*":[0-9]+"' /etc/hysteria/config.json 2>/dev/null | grep -oE '[0-9]+' | tail -1)
ct_stat() {
    local col total=0 v
    [ -r /proc/net/stat/nf_conntrack ] || { echo "-"; return; }
    col=$(awk -v n="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==n){print i; exit}}' /proc/net/stat/nf_conntrack)
    [ -n "$col" ] || { echo "غير متاح"; return; }
    while read -r v; do
        [ -z "$v" ] && continue
        case "$v" in *[!0-9a-fA-F]*) continue;; esac
        total=$(( total + 16#$v ))
    done < <(awk -v c="$col" 'NR>1{print $c}' /proc/net/stat/nf_conntrack)
    echo "$total"
}
echo "════════════ الأهم: اختبار التصفح عبر النفق ════════════"
hy-test 2>&1 | sed 's/^/  /'
echo
echo "════════════ منفذ الاستماع ════════════"
P "المنفذ:" "${PORT:-?}"
P "محجوز في النواة:" "$(cat /proc/sys/net/ipv4/ip_local_reserved_ports 2>/dev/null || echo -)"
echo
echo "════════════ تصادم NAT عند القفز ════════════"
P "insert_failed:" "$(ct_stat insert_failed)"
P "مهلة UDP العامة:" "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null)s"
if iptables -t raw -S HY_RAW 2>/dev/null | grep -q 'CT --timeout'; then
    P "مهلة القفز القصيرة:" "مفعّلة (nfct)"
elif nft list table ip hyhop >/dev/null 2>&1; then
    P "مهلة القفز القصيرة:" "مفعّلة (nftables)"
else
    P "مهلة القفز القصيرة:" "غير مفعّلة"
fi
P "نطاق القفز:" "$(iptables -t nat -S HY_HOP 2>/dev/null | grep -oE 'dports? [0-9:]+' | tail -1)"
echo
echo "════════════ إعدادات hysteria ════════════"
grep -E 'resolver|resolve_preference|disable_mtu|up_mbps|down_mbps' /etc/hysteria/config.json 2>/dev/null
echo
echo "════════════ خروج السيرفر ════════════"
P "ترجمة google.com:" "$(getent ahostsv4 www.google.com >/dev/null 2>&1 && echo نعم || echo 'لا  <-- مشكلة')"
P "الوصول إلى 1.1.1.1:443:" "$(T 1.1.1.1 443)"
echo
echo "════════════ أخطاء السجل ════════════"
journalctl -u hysteria-server -n 300 --no-pager 2>/dev/null \
  | grep -iE 'error|fail|refus|address already|no such host' | tail -10 || echo "لا أخطاء"
EOFD
chmod +x /usr/local/bin/hy-doctor

# ==================================================== 7) التحقق النهائي
log "التحقق من استقرار الخدمة..."
sleep 8

echo
if ! systemctl is-active --quiet "$SVC" || ! port_busy "$LISTEN_PORT"; then
    warn "الخدمة لم تستقر. مخرجات السجل:"
    journalctl -u "$SVC" -n 30 --no-pager || true
    exit 1
fi
ok "الخدمة تعمل"

echo
log "اختبار التصفح فعلياً عبر النفق (قد يستغرق دقيقة)..."
if ! command -v curl >/dev/null 2>&1; then
    (DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y curl >/dev/null 2>&1) || true
fi
echo
hy-test || true

echo
echo "════════════ اضبط التطبيق بهذه القيم حرفياً ════════════"
echo " UDP Server     : ${PUBIP:-<IP السيرفر>}"
echo " UDP Port       : ${HOP_START}-${HOP_END}"
if [ "$ENABLE_OBFS" = "1" ]; then
    echo " Obfs           : ${OBFS_PASS}"
else
    echo " Obfs           : (اتركه فارغاً)"
fi
echo " Auth           : ${FIRST_PASS}"
echo " Up Down Limit  : ${UP_MBPS}:${DOWN_MBPS}"
echo "════════════════════════════════════════════════════════"
echo " مسار الإنترنت  : IPv$( [ "$RESOLVE_PREF" = "4" ] && echo '4 فقط' || echo '4 ثم 6')"
echo " خادم DNS       : ${RESOLVER:-DNS النظام}"
echo
if [ -n "${OLD_PASS:-}" ] && [ "$OLD_PASS" = "$FIRST_PASS" ]; then
    ok "كلمة المرور كما هي."
else
    warn "كلمة المرور جديدة! حدّث خانة Auth في التطبيق."
fi
echo
echo " اختبار التصفح:  hy-test        تشخيص شامل:  hy-doctor"
