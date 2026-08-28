#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — Hysteria v1 UDP Server  (نسخة مُصلَّحة ومُحسَّنة)
#  Hysteria 1 فقط — ملف إعداد JSON
#
#  ★ إصلاح "Connection Lost" بعد ثوانٍ من الاتصال ★
#
#  السبب: تصادم في جدول NAT عند قفز المنافذ.
#  عند القفز من منفذ إلى آخر مع بقاء منفذ مصدر العميل ثابتاً، يحتاج النظام
#  إنشاء سجل NAT جديد يحمل نفس "زوج العودة" (36712 ← العميل) الخاص بالسجل
#  القديم. التصادم يجعل النواة تُسقط كل حزم المنفذ الجديد حتى ينتهي عمر
#  السجل القديم. جعلتُ عمره 60 ثانية، فصار انقطاعاً كاملاً بعد كل قفزة.
#  القيمة 5 في سكربتك الأصلي لم تكن خطأ — كانت التفافاً على هذا التصادم،
#  لكنها كانت تُطبَّق على كل شيء فتكسر حركة التصفح.
#
#  الحل هنا: مهلة قصيرة **لحركة القفز وحدها** عبر هدف CT، ومهلة طبيعية
#  لبقية الحركة. وإن تعذّر ذلك يُضيَّق نطاق القفز بحيث لا يتقاطع مع منافذ
#  السيرفر الصادرة، فتصبح المهلة القصيرة الشاملة آمنة.
#
#  الاستخدام:
#    sudo PASSWORDS="2a1d4b9896e:7823f72fcd10:16fbcee5gf" bash udp-hysteria-server.sh
#  تشخيص:  hy-doctor
# ==============================================================================

set -Eeuo pipefail

# ----------------------------------------------------------------- الإعدادات
LISTEN_PORT="${LISTEN_PORT:-36712}"
ENABLE_HOP="${ENABLE_HOP:-1}"
HOP_START="${HOP_START:-1}"
HOP_END="${HOP_END:-65535}"      # قد يُضيَّق تلقائياً إن لم تتوفر أداة nfct

UP_MBPS="${UP_MBPS:-100}"        # الحد الأقصى لكل عميل — يطابق 100:100 في التطبيق
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

# حدود منافذ السيرفر الصادرة — نطاق القفز يجب ألا يتقاطع معها في الوضع البديل
EPH_START=30000
EPH_END=65000

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

jq_() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
tcp_probe() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then die "يجب تشغيل السكربت بصلاحيات root."; fi
for t in iptables openssl timeout; do
    command -v "$t" >/dev/null 2>&1 || die "$t غير مثبت."
done
if [ ! -x "$HY_BIN" ]; then die "ملف hysteria التنفيذي غير موجود في $HY_BIN"; fi

HY_VER_RAW="$("$HY_BIN" version 2>/dev/null || "$HY_BIN" --version 2>/dev/null || "$HY_BIN" -v 2>/dev/null || echo '')"
if printf '%s' "$HY_VER_RAW" | grep -qiE '\bv?2\.[0-9]+\.[0-9]+'; then
    die "الملف التنفيذي في $HY_BIN هو Hysteria 2 وليس v1.
نزّل آخر إصدار من v1 (v1.3.5):
  systemctl stop ${SVC} 2>/dev/null
  wget -O /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64
  chmod +x /usr/local/bin/hysteria"
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

# ============ اختيار طريقة التعامل مع تصادم NAT عند القفز ============
# الوضع الأول (الأفضل): مهلة قصيرة لحركة القفز فقط عبر هدف CT.
#   يبقى نطاق القفز 1-65535 كما في التطبيق، وتبقى مهلة بقية الحركة 60 ثانية.
# الوضع البديل: تضييق نطاق القفز ليبتعد عن منافذ السيرفر الصادرة،
#   عندها تصبح المهلة القصيرة الشاملة آمنة ولا تكسر التصفح.
HOP_CT_MODE=0
if [ "$ENABLE_HOP" = "1" ]; then
    if ! command -v nfct >/dev/null 2>&1; then
        log "تثبيت conntrack-tools للحصول على أفضل أداء للقفز..."
        (DEBIAN_FRONTEND=noninteractive apt-get install -y conntrack >/dev/null 2>&1 \
         || yum install -y conntrack-tools >/dev/null 2>&1 \
         || dnf install -y conntrack-tools >/dev/null 2>&1) || true
    fi
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    if command -v nfct >/dev/null 2>&1 && nfct timeout list >/dev/null 2>&1; then
        HOP_CT_MODE=1
    fi
fi

if [ "$ENABLE_HOP" = "1" ] && [ "$HOP_CT_MODE" = "1" ]; then
    CT_UDP_TIMEOUT=60
    CT_UDP_STREAM=180
    ok "الوضع الأمثل: مهلة قصيرة لحركة القفز وحدها (نطاق ${HOP_START}-${HOP_END} كما هو)"
elif [ "$ENABLE_HOP" = "1" ]; then
    # لا تتوفر nfct — نضيّق النطاق ونستخدم مهلة قصيرة شاملة بأمان
    HOP_NARROWED=0
    if [ "$HOP_END" -ge "$EPH_START" ]; then
        HOP_END=$(( EPH_START - 1 ))
        HOP_NARROWED=1
    fi
    CT_UDP_TIMEOUT=5
    CT_UDP_STREAM=15
    warn "أداة nfct غير متاحة — استُخدم الوضع البديل."
    [ "$HOP_NARROWED" = "1" ] && warn "ضُيِّق نطاق القفز إلى ${HOP_START}-${HOP_END} (يجب تحديثه في التطبيق)."
else
    CT_UDP_TIMEOUT=60
    CT_UDP_STREAM=180
fi

# ============ اختبار خروج الإنترنت من السيرفر ============
log "اختبار اتصال السيرفر بالإنترنت..."
IPV6_OK=0
if [ "$FORCE_IPV6" = "1" ]; then
    IPV6_OK=1
elif [ "$FORCE_IPV6" = "auto" ] && ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    if tcp_probe "2606:4700:4700::1111" 443; then IPV6_OK=1; fi
fi
if [ "$IPV6_OK" = "1" ]; then
    RESOLVE_PREF="46"; ok "IPv6 يعمل — سيُستخدم كاحتياطي بعد IPv4"
else
    RESOLVE_PREF="4"
    if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
        warn "للسيرفر عنوان IPv6 لكنه لا يصل للإنترنت — فُرض IPv4 فقط."
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
    warn "السيرفر لا يستطيع ترجمة google.com عبر DNS النظام — راجع /etc/resolv.conf."
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

# --- udp_mem: نرفع فقط ولا نخفض تحت افتراضي النواة أبداً ---
read -r UM_MIN UM_PRESS UM_MAX < /proc/sys/net/ipv4/udp_mem 2>/dev/null || { UM_MIN=0; UM_PRESS=0; UM_MAX=0; }
UDP_MEM_MAX=$(( RAM_MB * 256 / 4 ))
[ "$UDP_MEM_MAX" -lt "$UM_MAX" ] && UDP_MEM_MAX="$UM_MAX"
UDP_MEM_PRESS=$(( UDP_MEM_MAX * 3 / 4 ))
[ "$UDP_MEM_PRESS" -lt "$UM_PRESS" ] && UDP_MEM_PRESS="$UM_PRESS"
UDP_MEM_MIN=$(( UDP_MEM_MAX / 4 ))
[ "$UDP_MEM_MIN" -lt "$UM_MIN" ] && UDP_MEM_MIN="$UM_MIN"

mkdir -p "$HY_DIR"

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
log "كتابة إعدادات النواة..."
modprobe nf_conntrack 2>/dev/null || true
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi

cat > /etc/sysctl.d/99-hysteria-multiuser.conf <<EOF
# ===== Hysteria v1 / QUIC tuning — MinaProNet =====

# --- مهلة تتبّع UDP ---
# تُضبط تلقائياً حسب طريقة التعامل مع تصادم NAT عند قفز المنافذ.
net.netfilter.nf_conntrack_udp_timeout = ${CT_UDP_TIMEOUT}
net.netfilter.nf_conntrack_udp_timeout_stream = ${CT_UDP_STREAM}
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# --- سقف مخازن المقابس: قيمة عالية بلا تكلفة ذاكرة (سقف لا تخصيص) ---
# مقبس استماع واحد يخدم كل المستخدمين، لذا خفضه يُسقط الحزم تحت الحِمل.
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
    cat >> /etc/sysctl.d/99-hysteria-multiuser.conf <<'EOF'

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
fi

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-hysteria-multiuser.conf >/dev/null 2>&1 || true
ok "إعدادات النواة مطبَّقة (udp_timeout=${CT_UDP_TIMEOUT}s | rmem_max=64MB | conntrack=${CT_MAX})"

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

build_config() {   # $1 = صيغة المصادقة: array | object ، $2 = مسار الملف
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
    probe_port=$(( (RANDOM % 4000) + 45000 ))
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
    AUTH_STYLE="object"; warn "إصدار قديم: mode=password (كلمة مرور واحدة فقط)."
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
log "إعادة بناء قواعد الجدار الناري..."

cat > "$HY_DIR/firewall.sh" <<EOFW
#!/usr/bin/env bash
# قواعد Hysteria — سلاسل مخصصة لا تمسح قواعد الخدمات الأخرى
set -uo pipefail
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
    iptables -t nat -D PREROUTING \${spec#-A PREROUTING } 2>/dev/null || true
done < <(iptables-save -t nat 2>/dev/null | grep -E '^-A PREROUTING .*REDIRECT.*(dport|dports) (1:65535|1-65535)' || true)

while iptables -C INPUT -p udp -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp -j ACCEPT 2>/dev/null || break
done

# ==================== جدول raw: مهلة قصيرة لحركة القفز وحدها ====================
# هذا هو إصلاح "Connection Lost". سجلات NAT الخاصة بالمنافذ المقفوزة تنتهي
# خلال ثوانٍ قليلة فيزول التصادم فوراً عند كل قفزة، بينما تحتفظ بقية حركة
# السيرفر بمهلة 60 ثانية الطبيعية فلا يتأثر التصفح.
iptables -t raw -N HY_RAW 2>/dev/null || true
iptables -t raw -F HY_RAW
iptables -t raw -C PREROUTING -j HY_RAW 2>/dev/null || iptables -t raw -I PREROUTING 1 -j HY_RAW

if [ "\$ENABLE_HOP" = "1" ] && [ "\$HOP_CT_MODE" = "1" ]; then
    modprobe nfnetlink_cttimeout 2>/dev/null || true
    nfct timeout delete hyhop >/dev/null 2>&1 || true
    nfct timeout add hyhop inet udp unreplied 5 replied 8 >/dev/null 2>&1 || true
    iptables -t raw -A HY_RAW -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j CT --timeout hyhop 2>/dev/null \\
        || echo "تحذير: تعذّر تطبيق سياسة المهلة القصيرة للقفز" >&2
fi

# ============================ سلسلة قفز المنافذ ============================
iptables -t nat -N HY_HOP 2>/dev/null || true
iptables -t nat -F HY_HOP
iptables -t nat -C PREROUTING -j HY_HOP 2>/dev/null || iptables -t nat -I PREROUTING 1 -j HY_HOP

if [ "\$ENABLE_HOP" = "1" ]; then
    # استثناءات إجبارية: بدونها تلتهم القاعدة حزم DHCP الخاصة بالسيرفر
    # فينقطع عنه الإنترنت عند تجديد الـ IP.
    EXCLUDE="67 68 546 547"
    if command -v ss >/dev/null 2>&1; then
        OTHERS=\$(ss -lun 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if(\$i ~ /:[0-9]+\$/){sub(/.*:/,"",\$i); print \$i; break}}' \\
                 | grep -E '^[0-9]+\$' | sort -un || true)
        EXCLUDE="\$EXCLUDE \$OTHERS"
    fi
    for p in \$EXCLUDE; do
        case "\$p" in ''|*[!0-9]*) continue;; esac
        [ "\$p" = "\$LISTEN_PORT" ] && continue
        [ "\$p" -lt "\$HOP_START" ] && continue
        [ "\$p" -gt "\$HOP_END" ] && continue
        iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$p" -j RETURN
    done

    iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT"
fi

# ============================ السماح في INPUT ============================
iptables -N HY_IN 2>/dev/null || true
iptables -F HY_IN
iptables -C INPUT -j HY_IN 2>/dev/null || iptables -I INPUT 1 -j HY_IN
# حركة العودة لاتصالات السيرفر الصادرة (DNS وHTTPS وكل ما يطلبه العملاء)
iptables -A HY_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \\
    || iptables -A HY_IN -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT

# ============================ IPv6 ============================
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY_IN 2>/dev/null || true
    ip6tables -F HY_IN 2>/dev/null || true
    ip6tables -C INPUT -j HY_IN 2>/dev/null || ip6tables -I INPUT 1 -j HY_IN 2>/dev/null || true
    ip6tables -A HY_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ip6tables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
    if [ "\$ENABLE_HOP" = "1" ]; then
        ip6tables -t nat -N HY_HOP 2>/dev/null || true
        ip6tables -t nat -F HY_HOP 2>/dev/null || true
        ip6tables -t nat -C PREROUTING -j HY_HOP 2>/dev/null || ip6tables -t nat -I PREROUTING 1 -j HY_HOP 2>/dev/null || true
        for p in 546 547; do
            ip6tables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$p" -j RETURN 2>/dev/null || true
        done
        ip6tables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
            -j REDIRECT --to-ports "\$LISTEN_PORT" 2>/dev/null || true
    fi
fi

exit 0
EOFW

chown root:root "$HY_DIR/firewall.sh"
chmod 700 "$HY_DIR/firewall.sh"
bash "$HY_DIR/firewall.sh" || warn "تحذير: بعض قواعد الجدار الناري لم تُطبَّق."
if [ "$ENABLE_HOP" = "1" ]; then
    ok "قفز المنافذ: ${HOP_START}-${HOP_END} ← ${LISTEN_PORT} على ${IFACE}"
else
    ok "منفذ واحد: ${LISTEN_PORT}"
fi

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
systemctl enable hysteria-firewall.service >/dev/null 2>&1 || true
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC" || true

# ======================================================== 6) أدوات الفحص
cat > /usr/local/bin/hy-status <<EOF
#!/usr/bin/env bash
echo "== حالة الخدمة =="
systemctl --no-pager -l status ${SVC} | head -10
echo; echo "== منفذ الاستماع =="
ss -lunp 2>/dev/null | grep -E ":${LISTEN_PORT}[[:space:]]" || echo "!! لا يوجد استماع على ${LISTEN_PORT}"
echo; echo "== عدّادات قفز المنافذ =="
iptables -t nat -L HY_HOP -n -v 2>/dev/null | tail -n +3
echo; echo "== سياسة المهلة القصيرة =="
iptables -t raw -L HY_RAW -n -v 2>/dev/null | tail -n +3
echo; echo "== conntrack =="
echo "\$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) / \$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
echo; echo "== آخر 20 سطر من السجل =="
journalctl -u ${SVC} -n 20 --no-pager
EOF
chmod +x /usr/local/bin/hy-status

cat > /usr/local/bin/hy-doctor <<'EOFD'
#!/usr/bin/env bash
P() { printf '%-44s %s\n' "$1" "$2"; }
T() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 && echo "نعم" || echo "لا"; }

# جمع عمود سداسي عشري من /proc/net/stat/nf_conntrack حسب اسمه
# (mawk الافتراضي لا يدعم strtonum، لذا الجمع يتم في bash)
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

echo "════════════ تصادم NAT عند القفز (سبب Connection Lost) ════════════"
P "insert_failed (تصادم NAT):" "$(ct_stat insert_failed)   <-- يجب أن يبقى شبه ثابت"
P "drop (حزم مُسقطة):" "$(ct_stat drop)"
P "clash_resolve:" "$(ct_stat clash_resolve)"
P "مهلة UDP العامة:" "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null)s"
if command -v nfct >/dev/null 2>&1; then
    if nfct timeout list 2>/dev/null | grep -q hyhop; then
        P "سياسة hyhop القصيرة:" "مفعّلة"
    else
        P "سياسة hyhop القصيرة:" "غير مفعّلة"
    fi
else
    P "أداة nfct:" "غير مثبتة (الوضع البديل)"
fi
if iptables -t raw -S HY_RAW 2>/dev/null | grep -q 'CT --timeout'; then
    P "قاعدة CT في جدول raw:" "موجودة"
else
    P "قاعدة CT في جدول raw:" "لا توجد"
fi
echo
echo "════════════ سعة السيرفر ════════════"
P "conntrack مستخدم/أقصى:" "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)/$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
P "rmem_max:" "$(( $(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 0) / 1048576 )) MB"
P "udp_mem (min/pressure/max):" "$(cat /proc/sys/net/ipv4/udp_mem 2>/dev/null)"
echo "--- أخطاء استقبال UDP (ارتفاعها = فقد حزم تحت الحِمل) ---"
netstat -su 2>/dev/null | grep -iE 'receive errors|RcvbufErrors|SndbufErrors' || echo "netstat غير مثبت"
echo "--- هل قُتلت الخدمة بسبب نفاد الذاكرة؟ ---"
dmesg 2>/dev/null | grep -i 'killed process.*hysteria' | tail -3 || echo "لا"
dmesg 2>/dev/null | grep -i 'nf_conntrack: table full' | tail -3 || true
echo
echo "════════════ خروج السيرفر إلى الإنترنت ════════════"
P "ترجمة google.com:" "$(getent hosts google.com >/dev/null 2>&1 && echo نعم || echo 'لا  <-- مشكلة')"
P "الوصول إلى 1.1.1.1:443:" "$(T 1.1.1.1 443)"
GIP=$(getent ahostsv4 www.youtube.com 2>/dev/null | awk '{print $1; exit}')
[ -n "$GIP" ] && P "الوصول إلى youtube ($GIP):" "$(T "$GIP" 443)"
if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    P "الوصول عبر IPv6:" "$(T 2606:4700:4700::1111 443)"
fi
echo
echo "════════════ إعدادات hysteria الفعالة ════════════"
grep -E 'resolver|resolve_preference|disable_mtu|up_mbps|down_mbps' /etc/hysteria/config.json 2>/dev/null
echo
echo "════════════ أخطاء السجل ════════════"
journalctl -u hysteria-server -n 300 --no-pager 2>/dev/null \
  | grep -iE 'error|fail|refus|timeout|no such host|denied' | tail -10 || echo "لا أخطاء"
EOFD
chmod +x /usr/local/bin/hy-doctor

# ==================================================== 7) التحقق النهائي
log "التحقق من استقرار الخدمة (12 ثانية)..."
sleep 12

echo
if systemctl is-active --quiet "$SVC" && ss -lunp 2>/dev/null | grep -qE ":${LISTEN_PORT}[[:space:]]"; then
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
    if [ "$ENABLE_HOP" = "1" ] && [ "$HOP_CT_MODE" = "1" ]; then
        ok "معالجة تصادم NAT: سياسة مهلة قصيرة لحركة القفز وحدها"
    elif [ "$ENABLE_HOP" = "1" ]; then
        warn "معالجة تصادم NAT: الوضع البديل — تأكّد أن UDP Port في التطبيق"
        warn "صار ${HOP_START}-${HOP_END} وليس 1-65535."
    fi
    echo
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
    exit 1
fi
