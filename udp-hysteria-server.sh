#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — Hysteria v1 UDP Server  (نسخة مُصلَّحة ومُحسَّنة)
#  Hysteria 1 فقط — ملف إعداد JSON
#
#  الإعدادات هنا مضبوطة لتطابق تطبيق MinaProNet VPN تماماً:
#     UDP Port  : 1-65535   (قفز على كامل المدى)
#     Obfs      : minapronet
#     Up/Down   : 100:100
#
#  الأسباب الحقيقية لتوقف الخدمة بعد ثوانٍ في السكربت الأصلي:
#   1) nf_conntrack_udp_timeout = 5 → موت جلسات UDP بعد 5 ثوانٍ من الخمول،
#      فتعود حزم الرد لتُخطف بقاعدة REDIRECT. هذا هو السبب الأول والأهم.
#   2) "auth": {"mode": "password"} صيغة غير موثقة في v1 → فشل فوري
#   3) Restart=on-failure بدون StartLimitIntervalSec=0 → توقف نهائي بعد 5 محاولات
#   4) المستخدم hysteria غير موجود أصلاً → فشل فوري عند كل تشغيل
#   5) rmem_default = 32MB → استنزاف الذاكرة واستدعاء OOM Killer
#   6) iptables -F INPUT → مسح قواعد النظام، و REDIRECT بلا استثناءات يكسر DHCP
#
#  الاستخدام:
#    sudo PASSWORDS="2a1d4b9896e:7823f72fcd10:16fbcee5gf" bash udp-hysteria-server.sh
# ==============================================================================

set -Eeuo pipefail

# ----------------------------------------------------------------- الإعدادات
LISTEN_PORT="${LISTEN_PORT:-36712}"      # المنفذ الحقيقي الذي يستمع عليه hysteria
ENABLE_HOP="${ENABLE_HOP:-1}"            # 1 = تفعيل قفز المنافذ
HOP_START="${HOP_START:-1}"              # يطابق خانة UDP Port في التطبيق
HOP_END="${HOP_END:-65535}"

# up_mbps / down_mbps في v1 هي الحد الأقصى **لكل عميل**.
# التطبيق يرسل 100:100 والسيرفر يأخذ الأصغر بين القيمتين، فاتركها 100.
UP_MBPS="${UP_MBPS:-100}"
DOWN_MBPS="${DOWN_MBPS:-100}"

OBFS_PASS="${OBFS_PASS:-minapronet}"     # يطابق خانة Obfs في التطبيق
ENABLE_OBFS="${ENABLE_OBFS:-1}"
ALPN="${ALPN:-}"                         # اتركه فارغاً إلا إذا كان التطبيق يحدده
RESOLVER="${RESOLVER:-udp://1.1.1.1:53}" # DNS مستقل عن /etc/resolv.conf
MAX_CONN_CLIENT="${MAX_CONN_CLIENT:-4096}"
DISABLE_MTU_DISC="${DISABLE_MTU_DISC:-false}"
LOG_LEVEL="${LOG_LEVEL:-info}"           # debug لعرض تفاصيل فشل المصادقة
ENABLE_BBR="${ENABLE_BBR:-1}"
SNI="${SNI:-www.bing.com}"
HY_DIR="/etc/hysteria"
HY_BIN="${HY_BIN:-/usr/local/bin/hysteria}"
SVC="hysteria-server"

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

# اقتباس JSON آمن: كلمة مرور فيها " أو \ كانت تُفسد الملف
jq_() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

if [ "$(id -u)" -ne 0 ]; then die "يجب تشغيل السكربت بصلاحيات root."; fi
for t in iptables openssl timeout; do
    command -v "$t" >/dev/null 2>&1 || die "$t غير مثبت."
done
if [ ! -x "$HY_BIN" ]; then die "ملف hysteria التنفيذي غير موجود في $HY_BIN"; fi

# --------------------------------------- التأكد أن الملف التنفيذي v1 وليس v2
HY_VER_RAW="$("$HY_BIN" version 2>/dev/null || "$HY_BIN" --version 2>/dev/null || "$HY_BIN" -v 2>/dev/null || echo '')"
if printf '%s' "$HY_VER_RAW" | grep -qiE '\bv?2\.[0-9]+\.[0-9]+'; then
    die "الملف التنفيذي في $HY_BIN هو Hysteria 2 وليس v1.
هذا السكربت لـ v1 فقط. نزّل آخر إصدار من v1 (v1.3.5):
  systemctl stop ${SVC} 2>/dev/null
  wget -O /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64
  chmod +x /usr/local/bin/hysteria
ثم أعد تشغيل هذا السكربت."
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

# نوافذ QUIC تُحسب من الذاكرة. الافتراضي في v1 هو 15MB و64MB **لكل عميل**،
# وقيم سكربتك (32MB/128MB) كانت الضِعف وتستنزف الذاكرة مع كثرة المستخدمين.
if [ "$RAM_MB" -le 1200 ]; then
    RECV_CONN=8388608;  RECV_CLIENT=33554432; SOCK_MAX=8388608
else
    RECV_CONN=15728640; RECV_CLIENT=67108864; SOCK_MAX=16777216
fi

CT_MAX=$(( RAM_MB * 256 ))
if [ "$CT_MAX" -gt 1048576 ]; then CT_MAX=1048576; fi
if [ "$CT_MAX" -lt 131072 ];  then CT_MAX=131072;  fi
CT_BUCKETS=$(( CT_MAX / 4 ))
UDP_MEM_MAX=$(( RAM_MB * 256 / 8 ))
UDP_MEM_PRESS=$(( UDP_MEM_MAX * 3 / 4 ))
UDP_MEM_MIN=$(( UDP_MEM_MAX / 4 ))

if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    RESOLVE_PREF="46"
else
    RESOLVE_PREF="4"
fi

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
# آخر ملاذ: استخراجها من أحدث نسخة احتياطية
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
log "كتابة إعدادات النواة المُحسَّنة..."
modprobe nf_conntrack 2>/dev/null || true
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi

cat > /etc/sysctl.d/99-hysteria-multiuser.conf <<EOF
# ===== Hysteria v1 / QUIC tuning — MinaProNet =====

# --- أهم سطرين في الملف كله ---
# القيمة 5 التي كانت في سكربتك تقتل سجل الاتصال بعد 5 ثوانٍ من الخمول،
# فتصبح حزمة الرد "جديدة" وتقع في قاعدة REDIRECT فتضيع. هذا سبب
# انقطاع الخدمة بعد ثوانٍ بالضبط. القيم أدناه هي المعيارية والآمنة.
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# --- مخازن UDP: نرفع الحد الأقصى فقط ونُبقي الافتراضي صغيراً.
# rmem_default الكبير يُطبَّق على كل مقبس في النظام لا على hysteria وحده.
net.core.rmem_max = ${SOCK_MAX}
net.core.wmem_max = ${SOCK_MAX}
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 32768
net.core.somaxconn = 16384

# --- حدود ذاكرة UDP على مستوى النظام (بالصفحات) لآلاف الجلسات
net.ipv4.udp_mem = ${UDP_MEM_MIN} ${UDP_MEM_PRESS} ${UDP_MEM_MAX}
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- حركة TCP الصادرة من الوكيل
net.ipv4.ip_local_port_range = 30000 65000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_max_tw_buckets = 262144
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# --- حدود الملفات لعدد مستخدمين غير محدود
fs.file-max = 2097152
fs.nr_open = 2097152

net.ipv4.ip_forward = 1
EOF

if [ "$ENABLE_BBR" = "1" ] && modprobe tcp_bbr 2>/dev/null; then
    cat >> /etc/sysctl.d/99-hysteria-multiuser.conf <<'EOF'

# --- BBR + fq لتحسين حركة TCP الصادرة من الوكيل
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
fi

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-hysteria-multiuser.conf >/dev/null 2>&1 || true
CT_NOW=$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null || echo '?')
ok "إعدادات النواة مطبَّقة (udp_timeout=${CT_NOW}s | conntrack=${CT_MAX})"

cat > /etc/security/limits.d/99-hysteria.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

# ==================================================== 2) المستخدم والشهادة
if ! id -u hysteria >/dev/null 2>&1; then
    log "إنشاء مستخدم الخدمة hysteria (كان مفقوداً تماماً)..."
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
# المجلد يبقى ملكاً لـ root: لو ملكه مستخدم الخدمة لأمكنه استبدال firewall.sh
# الذي يعمل بصلاحيات root.
chown root:hysteria "$HY_DIR" "$HY_DIR/server.key" "$HY_DIR/server.crt"
chmod 750 "$HY_DIR"
chmod 640 "$HY_DIR/server.key"
chmod 644 "$HY_DIR/server.crt"

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
    local style="$1" path="$2" auth_block obfs_line="" alpn_line=""

    if [ "$style" = "array" ]; then
        # الصيغة الموثقة رسمياً في v1: mode=passwords و config مصفوفة نصوص
        auth_block="\"auth\": { \"mode\": \"passwords\", \"config\": $(pw_array) },"
    else
        # صيغة الإصدارات القديمة جداً من v1
        auth_block="\"auth\": { \"mode\": \"password\", \"config\": { \"password\": $(jq_ "$FIRST_PASS") } },"
    fi

    if [ "$ENABLE_OBFS" = "1" ]; then obfs_line="    \"obfs\": $(jq_ "$OBFS_PASS"),"; fi
    if [ -n "$ALPN" ];            then alpn_line="    \"alpn\": $(jq_ "$ALPN"),";     fi

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
    "resolver": "${RESOLVER}",
    "resolve_preference": "${RESOLVE_PREF}"
}
EOF
    sed -i '/^[[:space:]]*$/d' "$path"
}

# --- اختبار الصيغة على الملف التنفيذي نفسه بدل التخمين ---
PROBE_OUT=""
probe_auth_style() {
    local style="$1" tmp probe_port out rc save_port
    tmp="$(mktemp /tmp/hy-probe.XXXXXX.json)"
    probe_port=$(( (RANDOM % 4000) + 45000 ))
    save_port="$LISTEN_PORT"
    LISTEN_PORT="$probe_port"
    build_config "$style" "$tmp"
    LISTEN_PORT="$save_port"

    rc=0
    out=$(timeout 4 "$HY_BIN" server --config "$tmp" 2>&1) || rc=$?
    rm -f "$tmp"
    PROBE_OUT="$out"
    # الرمز 124 يعني أن العملية كانت ما تزال تعمل عند انتهاء المهلة ⇒ الإعداد صالح
    [ "$rc" -eq 124 ]
}

log "اختبار صيغة المصادقة المدعومة في هذا الإصدار..."
AUTH_STYLE=""
if probe_auth_style "array"; then
    AUTH_STYLE="array"
    ok "الصيغة المدعومة: mode=passwords (مصفوفة)"
elif probe_auth_style "object"; then
    AUTH_STYLE="object"
    warn "إصدار قديم: mode=password (كائن). يدعم كلمة مرور واحدة فقط."
else
    echo "$PROBE_OUT" | tail -20
    die "فشل تشغيل hysteria بأي من الصيغتين. راجع المخرجات أعلاه."
fi

STAMP=$(date +%s)
if [ -f "$HY_DIR/config.json" ]; then cp -a "$HY_DIR/config.json" "$HY_DIR/config.json.bak.$STAMP"; fi
build_config "$AUTH_STYLE" "$HY_DIR/config.json"
chown root:hysteria "$HY_DIR/config.json"
chmod 640 "$HY_DIR/config.json"
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
IFACE="${IFACE}"

# --- حذف القواعد القديمة المكتوبة مباشرة في PREROUTING ---
while read -r spec; do
    [ -z "\$spec" ] && continue
    # shellcheck disable=SC2086
    iptables -t nat -D PREROUTING \${spec#-A PREROUTING } 2>/dev/null || true
done < <(iptables-save -t nat 2>/dev/null | grep -E '^-A PREROUTING .*REDIRECT.*(dport|dports) (1:65535|1-65535)' || true)

# --- حذف قاعدة السماح المفتوحة لكل UDP التي كان السكربت القديم يضيفها ---
while iptables -C INPUT -p udp -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp -j ACCEPT 2>/dev/null || break
done

# ============================ سلسلة قفز المنافذ ============================
iptables -t nat -N HY_HOP 2>/dev/null || true
iptables -t nat -F HY_HOP
iptables -t nat -C PREROUTING -j HY_HOP 2>/dev/null || iptables -t nat -I PREROUTING 1 -j HY_HOP

if [ "\$ENABLE_HOP" = "1" ]; then
    # --- استثناءات إجبارية قبل إعادة التوجيه ---
    # بدونها تلتهم القاعدة حزم DHCP الخاصة بالسيرفر نفسه فينقطع عنه الإنترنت
    # عند تجديد عنوان الـ IP، وتخطف أيضاً منافذ أي خدمة UDP أخرى على الجهاز.
    EXCLUDE="67 68 546 547"
    if command -v ss >/dev/null 2>&1; then
        # العنوان المحلي هو أول حقل ينتهي بـ :رقم — أكثر ثباتاً من رقم حقل ثابت
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

    # --- إعادة التوجيه الفعلية ---
    iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT"
fi

# ============================ السماح في INPUT ============================
# الحزم المُعاد توجيهها تصل إلى INPUT وقد صار منفذها LISTEN_PORT،
# لذلك سطر واحد يكفي ولا داعي لفتح كل منافذ UDP كما كان يفعل السكربت القديم.
iptables -N HY_IN 2>/dev/null || true
iptables -F HY_IN
iptables -C INPUT -j HY_IN 2>/dev/null || iptables -I INPUT 1 -j HY_IN
iptables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT

# --- عند إيقاف القفز: تعطيل تتبّع الاتصالات لتوفير جدول conntrack ---
iptables -t raw -N HY_RAW 2>/dev/null || true
iptables -t raw -F HY_RAW
iptables -t raw -C PREROUTING -j HY_RAW 2>/dev/null || iptables -t raw -I PREROUTING 1 -j HY_RAW
iptables -t raw -D OUTPUT -p udp --sport "\$LISTEN_PORT" -j NOTRACK 2>/dev/null || true
if [ "\$ENABLE_HOP" != "1" ]; then
    iptables -t raw -A HY_RAW -p udp --dport "\$LISTEN_PORT" -j NOTRACK
    iptables -t raw -I OUTPUT 1 -p udp --sport "\$LISTEN_PORT" -j NOTRACK
fi

# ============================ IPv6 ============================
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY_IN 2>/dev/null || true
    ip6tables -F HY_IN 2>/dev/null || true
    ip6tables -C INPUT -j HY_IN 2>/dev/null || ip6tables -I INPUT 1 -j HY_IN 2>/dev/null || true
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
    ok "قفز المنافذ مفعّل: ${HOP_START}-${HOP_END} ← ${LISTEN_PORT} على ${IFACE}"
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
# بدون هذين السطرين توقف systemd الخدمة نهائياً بعد 5 محاولات فاشلة خلال 10 ثوانٍ
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

# ======================================================== 6) أداة الفحص
cat > /usr/local/bin/hy-status <<EOF
#!/usr/bin/env bash
echo "== حالة الخدمة =="
systemctl --no-pager -l status ${SVC} | head -10
echo
echo "== منفذ الاستماع =="
ss -lunp 2>/dev/null | grep -E ":${LISTEN_PORT}[[:space:]]" || echo "!! لا يوجد استماع على ${LISTEN_PORT}"
echo
echo "== عدّادات قفز المنافذ (يجب أن ترتفع عند محاولة الاتصال) =="
iptables -t nat -L HY_HOP -n -v 2>/dev/null | tail -n +3
echo
echo "== عدّاد قبول الحزم =="
iptables -L HY_IN -n -v 2>/dev/null | tail -n +3
echo
echo "== conntrack =="
echo "الحالي: \$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -) / \$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -)"
echo "udp_timeout: \$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null || echo -)s"
echo
echo "== كلمة المرور المضبوطة على السيرفر =="
grep -o '"auth".*' /etc/hysteria/config.json 2>/dev/null | head -1
echo
echo "== آخر 20 سطر من السجل =="
journalctl -u ${SVC} -n 20 --no-pager
EOF
chmod +x /usr/local/bin/hy-status

# ==================================================== 7) التحقق النهائي
log "التحقق من استقرار الخدمة (12 ثانية)..."
sleep 12

echo
if systemctl is-active --quiet "$SVC" && ss -lunp 2>/dev/null | grep -qE ":${LISTEN_PORT}[[:space:]]"; then
    RESTARTS=$(systemctl show -p NRestarts --value "$SVC" 2>/dev/null || echo 0)
    ok "الخدمة تعمل بثبات (مرات إعادة التشغيل: ${RESTARTS})"
    echo
    echo "════════════ اضبط التطبيق بهذه القيم حرفياً ════════════"
    echo " UDP Server        : ${PUBIP:-<IP السيرفر>}"
    echo " UDP Port          : ${HOP_START}-${HOP_END}"
    if [ "$ENABLE_OBFS" = "1" ]; then
        echo " Obfs              : ${OBFS_PASS}"
    else
        echo " Obfs              : (اتركه فارغاً)"
    fi
    echo " Auth              : ${FIRST_PASS}"
    echo " Up Down Limit     : ${UP_MBPS}:${DOWN_MBPS}"
    echo "═══════════════════════════════════════════════════════"
    echo
    if [ -n "${OLD_PASS:-}" ] && [ "$OLD_PASS" = "$FIRST_PASS" ]; then
        ok "كلمة المرور مأخوذة من إعدادك السابق (لم تتغير)."
    else
        warn "كلمة المرور جديدة! يجب تحديث خانة Auth في التطبيق."
        warn "لتثبيت كلمة مرور محددة أعد التشغيل هكذا:"
        echo "  sudo PASSWORDS=\"القيمة_التي_في_التطبيق\" bash \$0"
    fi
    echo
    echo " لمتابعة محاولات الاتصال مباشرة أثناء الضغط على Connect:"
    echo "   journalctl -u ${SVC} -f"
    echo " وللفحص الشامل:  hy-status"
else
    warn "الخدمة لم تستقر. مخرجات السجل:"
    journalctl -u "$SVC" -n 30 --no-pager || true
    exit 1
fi
