#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — Hysteria v1 UDP Server  (نسخة مُصلَّحة ومُحسَّنة)
#
#  ★ إصلاحات هذا الإصدار ★
#  1) bind: address already in use
#     المنفذ 36712 يقع داخل نطاق منافذ النظام الصادرة (30000-65000)، فتخطفه
#     أي عملية تفتح اتصالاً خارجياً قبل أن يبدأ hysteria. الحل: حجزه في النواة
#     عبر ip_local_reserved_ports + تحرير المنفذ من أي عملية قديمة قبل التشغيل.
#  2) nfct غير متوفرة على Ubuntu 22.04
#     أُضيف بديل عبر nftables (متوفر افتراضياً) لتطبيق المهلة القصيرة على
#     حركة القفز وحدها، فيبقى نطاق 1-65535 كما في التطبيق دون تضييق.
#     ويُتحقَّق من نجاحه فعلياً، وإلا يُنتقل تلقائياً للوضع البديل.
#
#  الاستخدام:
#    sudo PASSWORDS="2a1d4b9896e:7823f72fcd10:16fbcee5gf" bash udp-hysteria-server.sh
#  تشخيص:  hy-doctor
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:$PATH"

# ----------------------------------------------------------------- الإعدادات
LISTEN_PORT="${LISTEN_PORT:-36712}"   # منفذ داخلي فقط — العملاء يستخدمون نطاق القفز
ENABLE_HOP="${ENABLE_HOP:-1}"
HOP_START="${HOP_START:-1}"
HOP_END="${HOP_END:-65535}"

UP_MBPS="${UP_MBPS:-100}"             # الحد الأقصى لكل عميل — يطابق 100:100
DOWN_MBPS="${DOWN_MBPS:-100}"

OBFS_PASS="${OBFS_PASS:-minapronet}"
ENABLE_OBFS="${ENABLE_OBFS:-1}"
ALPN="${ALPN:-}"
RESOLVER="${RESOLVER:-auto}"
FORCE_IPV6="${FORCE_IPV6:-auto}"
MAX_CONN_CLIENT="${MAX_CONN_CLIENT:-4096}"
DISABLE_MTU_DISC="${DISABLE_MTU_DISC:-true}"
LOG_LEVEL="${LOG_LEVEL:-info}"
ENABLE_BBR="${ENABLE_BBR:-1}"
SNI="${SNI:-www.bing.com}"
HY_DIR="/etc/hysteria"
HY_BIN="${HY_BIN:-/usr/local/bin/hysteria}"
SVC="hysteria-server"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-multiuser.conf"

EPH_START=30000     # نطاق منافذ السيرفر الصادرة
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
CPUS=$(nproc 2>/dev/null || echo 1)
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
if [ -z "${IFACE:-}" ]; then IFACE=$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}'); fi
[ -n "${IFACE:-}" ] || die "تعذّر تحديد واجهة الشبكة الخارجية."
PUBIP=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1 || true)
log "الموارد: ذاكرة ${RAM_MB}MB | معالجات ${CPUS} | واجهة ${IFACE} | IP ${PUBIP:-غير معروف}"

mkdir -p "$HY_DIR"

# ============ تحرير منفذ الاستماع قبل أي شيء ============
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
        warn "المنفذ ${port} محجوز من العملية ${pid} (${comm})${unit:+ ضمن الوحدة ${unit}}"
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
        # المنفذ محجوز من شيء لا يمكن إيقافه — نختار منفذاً حراً.
        # لا يؤثر ذلك على التطبيق لأن العملاء يتصلون عبر نطاق القفز.
        NEWP=""
        for _ in $(seq 1 60); do
            CAND=$(( (RANDOM % 9000) + 20000 ))
            if ! port_busy "$CAND"; then NEWP="$CAND"; break; fi
        done
        [ -n "$NEWP" ] || die "تعذّر إيجاد منفذ حر."
        warn "تعذّر تحرير ${LISTEN_PORT} — تم التحويل إلى المنفذ ${NEWP}"
        LISTEN_PORT="$NEWP"
    fi
else
    ok "المنفذ ${LISTEN_PORT} متاح"
fi

# ============ اختيار طريقة معالجة تصادم NAT عند القفز ============
# 0 = تضييق النطاق + مهلة قصيرة شاملة
# 1 = nfct   (conntrack-tools)
# 2 = nft    (nftables — متوفر افتراضياً على Ubuntu 22.04)
HOP_CT_MODE=0
if [ "$ENABLE_HOP" = "1" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true

    if ! command -v nfct >/dev/null 2>&1; then
        log "محاولة تثبيت conntrack-tools..."
        (DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y conntrack >/dev/null 2>&1 \
         || (timeout 180 apt-get update >/dev/null 2>&1 \
             && DEBIAN_FRONTEND=noninteractive timeout 120 apt-get install -y conntrack >/dev/null 2>&1) \
         || timeout 120 yum install -y conntrack-tools >/dev/null 2>&1 \
         || timeout 120 dnf install -y conntrack-tools >/dev/null 2>&1) || true
        hash -r 2>/dev/null || true
    fi

    if command -v nfct >/dev/null 2>&1 && nfct timeout list >/dev/null 2>&1; then
        HOP_CT_MODE=1
    elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        # اختبار حقيقي بنفس البنية التي ستُستخدم لاحقاً، ثم التحقق من وجودها
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
    1) ok "معالجة تصادم NAT عبر nfct — نطاق القفز ${HOP_START}-${HOP_END} يبقى كما هو" ;;
    2) ok "معالجة تصادم NAT عبر nftables — نطاق القفز ${HOP_START}-${HOP_END} يبقى كما هو" ;;
    *) [ "$ENABLE_HOP" = "1" ] && warn "لا nfct ولا nftables — الوضع البديل بنطاق ${HOP_START}-${HOP_END}" ;;
esac

# ============ اختبار خروج الإنترنت من السيرفر ============
log "اختبار اتصال السيرفر بالإنترنت..."
IPV6_OK=0
if [ "$FORCE_IPV6" = "1" ]; then
    IPV6_OK=1
elif [ "$FORCE_IPV6" = "auto" ] && ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    if tcp_probe "2606:4700:4700::1111" 443; then IPV6_OK=1; fi
fi
if [ "$IPV6_OK" = "1" ]; then
    RESOLVE_PREF="46"; ok "IPv6 يعمل"
else
    RESOLVE_PREF="4"
    if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
        warn "عنوان IPv6 موجود لكنه لا يصل للإنترنت — فُرض IPv4 فقط."
    else
        log "لا يوجد IPv6 — فُرض IPv4 فقط"
    fi
fi
if tcp_probe 1.1.1.1 443; then ok "خروج IPv4 يعمل"; else warn "تعذّر الوصول إلى 1.1.1.1:443"; fi

if [ "$RESOLVER" = "auto" ]; then
    RESOLVER=""
    for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
        if tcp_probe "$r" 53; then RESOLVER="udp://${r}:53"; break; fi
    done
    if [ -n "$RESOLVER" ]; then ok "خادم DNS المعتمد: ${RESOLVER}"
    else warn "لا يوجد خادم DNS عام يستجيب — سيُستخدم DNS النظام."; fi
fi
if ! getent hosts google.com >/dev/null 2>&1; then
    warn "السيرفر لا يستطيع ترجمة google.com — راجع /etc/resolv.conf."
fi

# نوافذ QUIC (الافتراضي في v1: 15MB و64MB لكل عميل)
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

# --- حجز منفذ الاستماع ---
# بدونه قد تخطف أي عملية تفتح اتصالاً خارجياً المنفذ ${LISTEN_PORT} لأنه يقع
# داخل نطاق المنافذ الصادرة، فيفشل hysteria بـ address already in use.
net.ipv4.ip_local_reserved_ports = ${LISTEN_PORT}

# --- مهلة تتبّع UDP ---
net.netfilter.nf_conntrack_udp_timeout = ${CT_UDP_TIMEOUT}
net.netfilter.nf_conntrack_udp_timeout_stream = ${CT_UDP_STREAM}
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# --- سقف مخازن المقابس (سقف لا تخصيص — بلا تكلفة ذاكرة) ---
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
    cat >> "$SYSCTL_FILE" <<'EOF'

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
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
    log "إنشاء مستخدم الخدمة hysteria..."
    useradd --system --no-create-home --shell /usr/sbin/nologin hysteria
fi

if [ ! -s "$HY_DIR/server.crt" ] || [ ! -s "$HY_DIR/server.key" ]; then
    log "توليد شهادة ذاتية التوقيع (10 سنوات)..."
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
# قواعد Hysteria — سلاسل مخصصة لا تمسح قواعد الخدمات الأخرى
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
# سجلات NAT للمنافذ المقفوزة تنتهي خلال ثوانٍ فيزول التصادم عند كل قفزة،
# بينما تحتفظ بقية حركة السيرفر بمهلة 60 ثانية فلا يتأثر التصفح.
iptables -t raw -N HY_RAW >/dev/null 2>&1 || true
iptables -t raw -F HY_RAW >/dev/null 2>&1
iptables -t raw -C PREROUTING -j HY_RAW >/dev/null 2>&1 || iptables -t raw -I PREROUTING 1 -j HY_RAW >/dev/null 2>&1
nft delete table ip hyhop >/dev/null 2>&1 || true

if [ "\$ENABLE_HOP" = "1" ] && [ "\$HOP_CT_MODE" = "1" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    nfct timeout delete hyhop >/dev/null 2>&1 || true
    nfct timeout add hyhop inet udp unreplied 5 replied 8 >/dev/null 2>&1 || true
    iptables -t raw -A HY_RAW -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j CT --timeout hyhop >/dev/null 2>&1 \\
        || echo "تحذير: تعذّر تطبيق سياسة المهلة القصيرة (nfct)" >&2
elif [ "\$ENABLE_HOP" = "1" ] && [ "\$HOP_CT_MODE" = "2" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    nft -f - >/dev/null 2>&1 <<NFT || echo "تحذير: تعذّر تطبيق سياسة المهلة القصيرة (nft)" >&2
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

# ============================ سلسلة قفز المنافذ ============================
iptables -t nat -N HY_HOP >/dev/null 2>&1 || true
iptables -t nat -F HY_HOP >/dev/null 2>&1
iptables -t nat -C PREROUTING -j HY_HOP >/dev/null 2>&1 || iptables -t nat -I PREROUTING 1 -j HY_HOP >/dev/null 2>&1

if [ "\$ENABLE_HOP" = "1" ]; then
    # استثناءات إجبارية: بدونها تلتهم القاعدة حزم DHCP الخاصة بالسيرفر
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

# ============================ IPv6 ============================
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY_IN >/dev/null 2>&1 || true
    ip6tables -F HY_IN >/dev/null 2>&1 || true
    ip6tables -C INPUT -j HY_IN >/dev/null 2>&1 || ip6tables -I INPUT 1 -j HY_IN >/dev/null 2>&1 || true
    ip6tables -A HY_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT >/dev/null 2>&1 || true
    if [ "\$ENABLE_HOP" = "1" ]; then
        ip6tables -t nat -N HY_HOP >/dev/null 2>&1 || true
        ip6tables -t nat -F HY_HOP >/dev/null 2>&1 || true
        ip6tables -t nat -C PREROUTING -j HY_HOP >/dev/null 2>&1 || ip6tables -t nat -I PREROUTING 1 -j HY_HOP >/dev/null 2>&1 || true
        for p in 546 547; do
            ip6tables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$p" -j RETURN >/dev/null 2>&1 || true
        done
        ip6tables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
            -j REDIRECT --to-ports "\$LISTEN_PORT" >/dev/null 2>&1 || true
    fi
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
bash "$HY_DIR/firewall.sh" || warn "تحذير: بعض قواعد الجدار الناري لم تُطبَّق."

# التحقق الفعلي من نجاح سياسة المهلة القصيرة، وإلا الانتقال للوضع البديل
if ! verify_hop_ct; then
    warn "فشل تطبيق سياسة المهلة القصيرة — الانتقال التلقائي للوضع البديل."
    HOP_CT_MODE=0
    apply_hop_mode
    write_sysctl
    write_firewall
    bash "$HY_DIR/firewall.sh" || true
    warn "ضُيِّق نطاق القفز إلى ${HOP_START}-${HOP_END} — حدّث خانة UDP Port في التطبيق."
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
# سكربت انتظار منفصل: كتابة المنطق داخل ExecStartPre تجعل systemd يحاول
# تفسير $i و$(...) كمتغيرات بيئة فيفسد الأمر.
cat > "$HY_DIR/wait-port.sh" <<EOF
#!/usr/bin/env bash
# ينتظر تحرّر منفذ الاستماع حتى 10 ثوانٍ ثم يخرج بنجاح في كل الأحوال
for i in \$(seq 1 10); do
    ss -lun 2>/dev/null | grep -qE "[:*.]${LISTEN_PORT}[[:space:]]" || exit 0
    sleep 1
done
exit 0
EOF
chown root:hysteria "$HY_DIR/wait-port.sh"
chmod 750 "$HY_DIR/wait-port.sh"

log "تحديث وحدة systemd..."
cat > "/etc/systemd/system/${SVC}.service" <<EOF
[Unit]
Description=Hysteria v1 UDP Server (MinaProNet)
Documentation=https://v1.hysteria.network/
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

# ======================================================== 6) أدوات الفحص
cat > /usr/local/bin/hy-status <<EOF
#!/usr/bin/env bash
export PATH="/usr/sbin:/sbin:\$PATH"
echo "== حالة الخدمة =="
systemctl --no-pager -l status ${SVC} | head -10
echo; echo "== منفذ الاستماع =="
ss -lunp 2>/dev/null | grep -E "[:*.]${LISTEN_PORT}[[:space:]]" || echo "!! لا يوجد استماع على ${LISTEN_PORT}"
echo; echo "== عدّادات قفز المنافذ =="
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

echo "════════════ منفذ الاستماع ════════════"
P "المنفذ المُعدّ:" "${PORT:-?}"
P "محجوز في النواة:" "$(cat /proc/sys/net/ipv4/ip_local_reserved_ports 2>/dev/null || echo -)"
echo "من يستمع عليه:"
ss -lunp 2>/dev/null | grep -E "[:*.]${PORT}[[:space:]]" || echo "  لا أحد!"
echo
echo "════════════ تصادم NAT عند القفز ════════════"
P "insert_failed (تصادم NAT):" "$(ct_stat insert_failed)   <-- يجب أن يبقى شبه ثابت"
P "drop:" "$(ct_stat drop)"
P "مهلة UDP العامة:" "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null)s"
if iptables -t raw -S HY_RAW 2>/dev/null | grep -q 'CT --timeout'; then
    P "سياسة المهلة القصيرة:" "مفعّلة عبر nfct"
elif nft list table ip hyhop >/dev/null 2>&1; then
    P "سياسة المهلة القصيرة:" "مفعّلة عبر nftables"
else
    P "سياسة المهلة القصيرة:" "غير مفعّلة (الوضع البديل)"
fi
P "نطاق القفز المطبَّق:" "$(iptables -t nat -S HY_HOP 2>/dev/null | grep -oE 'dports? [0-9:]+' | tail -1)"
echo
echo "════════════ سعة السيرفر ════════════"
P "conntrack مستخدم/أقصى:" "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)/$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
P "rmem_max:" "$(( $(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 0) / 1048576 )) MB"
echo "--- أخطاء استقبال UDP ---"
netstat -su 2>/dev/null | grep -iE 'receive errors|RcvbufErrors' || echo "netstat غير مثبت"
echo "--- قتل بسبب نفاد الذاكرة؟ ---"
dmesg 2>/dev/null | grep -i 'killed process.*hysteria' | tail -3 || echo "لا"
echo
echo "════════════ خروج السيرفر إلى الإنترنت ════════════"
P "ترجمة google.com:" "$(getent hosts google.com >/dev/null 2>&1 && echo نعم || echo 'لا  <-- مشكلة')"
P "الوصول إلى 1.1.1.1:443:" "$(T 1.1.1.1 443)"
GIP=$(getent ahostsv4 www.youtube.com 2>/dev/null | awk '{print $1; exit}')
[ -n "$GIP" ] && P "الوصول إلى youtube ($GIP):" "$(T "$GIP" 443)"
echo
echo "════════════ أخطاء السجل ════════════"
journalctl -u hysteria-server -n 300 --no-pager 2>/dev/null \
  | grep -iE 'error|fail|refus|address already|no such host' | tail -10 || echo "لا أخطاء"
EOFD
chmod +x /usr/local/bin/hy-doctor

# ==================================================== 7) التحقق النهائي
log "التحقق من استقرار الخدمة (12 ثانية)..."
sleep 12

echo
if systemctl is-active --quiet "$SVC" && port_busy "$LISTEN_PORT"; then
    RESTARTS=$(systemctl show -p NRestarts --value "$SVC" 2>/dev/null || echo 0)
    ok "الخدمة تعمل بثبات (مرات إعادة التشغيل: ${RESTARTS})"
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
    echo " (المنفذ الداخلي ${LISTEN_PORT} لا يُدخل في التطبيق)"
    echo
    case "$HOP_CT_MODE" in
        1) ok "تصادم NAT: مُعالَج عبر nfct" ;;
        2) ok "تصادم NAT: مُعالَج عبر nftables" ;;
        *) if [ "$ENABLE_HOP" = "1" ]; then
               warn "تصادم NAT: الوضع البديل — تأكّد أن UDP Port في التطبيق = ${HOP_START}-${HOP_END}"
           fi ;;
    esac
    if [ -n "${OLD_PASS:-}" ] && [ "$OLD_PASS" = "$FIRST_PASS" ]; then
        ok "كلمة المرور كما هي."
    else
        warn "كلمة المرور جديدة! حدّث خانة Auth في التطبيق."
    fi
    echo
    echo " للتشخيص:  hy-doctor        للفحص العام:  hy-status"
else
    warn "الخدمة لم تستقر. مخرجات السجل:"
    journalctl -u "$SVC" -n 30 --no-pager || true
    echo
    warn "من يستمع على المنفذ ${LISTEN_PORT}:"
    ss -lunp 2>/dev/null | grep -E "[:*.]${LISTEN_PORT}[[:space:]]" || echo "  لا أحد"
    exit 1
fi
