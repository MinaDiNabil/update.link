#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — Hysteria UDP Server  (نسخة مُصلَّحة ومُحسَّنة)
#  الهدف: ثبات دائم بلا انقطاع + عدد مستخدمين غير محدود + أقصى سرعة ممكنة
#
#  الأسباب الحقيقية لتوقف الخدمة بعد ثوانٍ في السكربت القديم:
#   1) REDIRECT على المنافذ 1:65535 كان يخطف حركة العودة الخاصة بالسيرفر نفسه
#   2) nf_conntrack_udp_timeout = 5 كان يقتل جلسات UDP بعد 5 ثوانٍ من الخمول
#   3) Restart=on-failure بلا StartLimitIntervalSec=0 يوقف الخدمة نهائياً
#   4) rmem_default = 32MB يلتهم الذاكرة ويستدعي OOM Killer
#   5) عدم تطابق صيغة ملف الإعداد مع إصدار Hysteria المثبّت
#   6) iptables -F INPUT يمسح قواعد النظام والمستخدم hysteria غير موجود أصلاً
#
#  الاستخدام:  sudo bash udp-hysteria-server.sh
#  تخصيص:      sudo LISTEN_PORT=443 ENABLE_OBFS=0 bash udp-hysteria-server.sh
# ==============================================================================

set -Eeuo pipefail

# ----------------------------------------------------------------- الإعدادات
LISTEN_PORT="${LISTEN_PORT:-36712}"          # منفذ الاستماع الأساسي
ENABLE_HOP="${ENABLE_HOP:-1}"                # 1 = تفعيل Port Hopping ضد حجب UDP
HOP_START="${HOP_START:-20000}"              # بداية نطاق القفز
HOP_END="${HOP_END:-29999}"                  # نهاية نطاق القفز
ENABLE_OBFS="${ENABLE_OBFS:-1}"              # 0 إذا كان التطبيق لا يدعم salamander
OBFS_PASS="${OBFS_PASS:-minapronet}"
ENABLE_BBR="${ENABLE_BBR:-1}"                # BBR + fq لحركة TCP الصادرة
IGNORE_CLIENT_BW="${IGNORE_CLIENT_BW:-1}"    # 1 = BBR للجميع (الأفضل لعدد كبير)
UP_MBPS="${UP_MBPS:-1000}"                   # تُستخدم فقط عند IGNORE_CLIENT_BW=0
DOWN_MBPS="${DOWN_MBPS:-1000}"
SNI="${SNI:-www.bing.com}"
MASQ_URL="${MASQ_URL:-https://www.bing.com}" # تمويه: السيرفر يبدو موقع HTTPS عادي
HY_DIR="/etc/hysteria"
HY_BIN="${HY_BIN:-/usr/local/bin/hysteria}"
SVC="hysteria-server"

# اقتباس آمن يمنع كسر الملفات بكلمات مرور تحوي رموزاً أو مسافات
# (كلمة مرور مثل yes أو 12345 تُفسَّر خطأً في YAML بدون اقتباس)
yq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }
jq_() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then die "يجب تشغيل السكربت بصلاحيات root."; fi
if ! command -v iptables >/dev/null 2>&1; then die "iptables غير مثبت: apt install -y iptables"; fi
if ! command -v openssl  >/dev/null 2>&1; then die "openssl غير مثبت: apt install -y openssl"; fi
if [ ! -x "$HY_BIN" ]; then die "ملف hysteria التنفيذي غير موجود في $HY_BIN"; fi
if [ "$HOP_END" -ge 30000 ] && [ "$ENABLE_HOP" = "1" ]; then
    die "نطاق القفز يجب أن ينتهي قبل 30000 حتى لا يتعارض مع منافذ المصدر الصادرة."
fi

# --------------------------------------------- كشف الموارد وواجهة الشبكة
RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
CPUS=$(nproc 2>/dev/null || echo 1)
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
if [ -z "${IFACE:-}" ]; then IFACE=$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}'); fi
PUBIP=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1 || true)
log "الموارد: ذاكرة ${RAM_MB}MB | معالجات ${CPUS} | واجهة ${IFACE} | IP ${PUBIP:-غير معروف}"

# نوافذ QUIC وحجم المخازن تُحسب من الذاكرة (يمنع OOM على السيرفرات الصغيرة)
if [ "$RAM_MB" -le 1200 ]; then
    STREAM_WIN=2097152;  CONN_WIN=5242880;  SOCK_MAX=8388608;  STREAMS=512
elif [ "$RAM_MB" -le 2500 ]; then
    STREAM_WIN=4194304;  CONN_WIN=10485760; SOCK_MAX=16777216; STREAMS=1024
else
    STREAM_WIN=8388608;  CONN_WIN=20971520; SOCK_MAX=16777216; STREAMS=2048
fi

# سعة conntrack تتناسب مع الذاكرة (كل سجل ≈ 350 بايت) بدل رقم ثابت خطير
CT_MAX=$(( RAM_MB * 256 ))
if [ "$CT_MAX" -gt 1048576 ]; then CT_MAX=1048576; fi
if [ "$CT_MAX" -lt 131072 ];  then CT_MAX=131072;  fi
CT_BUCKETS=$(( CT_MAX / 4 ))
UDP_MEM_MAX=$(( RAM_MB * 256 / 8 ))          # ≈ 12.5% من الذاكرة بوحدة الصفحات
UDP_MEM_PRESS=$(( UDP_MEM_MAX * 3 / 4 ))
UDP_MEM_MIN=$(( UDP_MEM_MAX / 4 ))

# ------------------------------------------------------ كشف إصدار Hysteria
HY_VER_RAW="$("$HY_BIN" version 2>/dev/null || "$HY_BIN" --version 2>/dev/null || "$HY_BIN" -v 2>/dev/null || echo '')"
VER_KNOWN=1
if   printf '%s' "$HY_VER_RAW" | grep -qiE '\bv?2\.[0-9]+\.[0-9]+'; then HY_MAJOR=2
elif printf '%s' "$HY_VER_RAW" | grep -qiE '\bv?1\.[0-9]+\.[0-9]+'; then HY_MAJOR=1
else
    HY_MAJOR=2; VER_KNOWN=0
    warn "تعذّر تحديد الإصدار — سيُجرَّب v2 أولاً ثم v1 تلقائياً عند الفشل."
fi
log "إصدار Hysteria: v${HY_MAJOR}"
if [ "$HY_MAJOR" -eq 1 ]; then
    warn "Hysteria 1 قديم ولم يعد مدعوماً. يُنصح بشدة بالترقية إلى v2."
fi

mkdir -p "$HY_DIR"

# ------------------------------------------ الحفاظ على كلمة المرور الحالية
OLD_PASS=""
if [ -f "$HY_DIR/config.yaml" ]; then
    OLD_PASS=$(awk '/^auth:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/password:/{sub(/^[[:space:]]*password:[[:space:]]*/,""); gsub(/["'"'"']/,""); print; exit}' "$HY_DIR/config.yaml" 2>/dev/null || true)
fi
if [ -z "$OLD_PASS" ] && [ -f "$HY_DIR/config.json" ]; then
    OLD_PASS=$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$HY_DIR/config.json" 2>/dev/null | head -1 | sed 's/.*"password"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)
fi
PASSWORD="${PASSWORD:-${OLD_PASS:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)}}"

# ============================================================ 1) إعدادات النواة
log "كتابة إعدادات النواة المُحسَّنة..."
modprobe nf_conntrack 2>/dev/null || true
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi

cat > /etc/sysctl.d/99-hysteria-multiuser.conf <<EOF
# ===== Hysteria / QUIC tuning — MinaProNet =====

# --- مخازن UDP: نرفع الحد الأقصى فقط ونُبقي الافتراضي صغيراً.
# rmem_default الكبير يخصّص ذاكرة لكل مقبس في النظام ويؤدي إلى OOM.
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

# --- تتبّع الاتصالات: مهلة واقعية بدل 5 ثوانٍ التي كانت تقطع الجلسات
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# --- منافذ المصدر الصادرة خارج نطاق القفز حتى لا تُخطف حركة العودة
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
ok "إعدادات النواة مطبَّقة (conntrack=${CT_MAX} | socket buffer=$((SOCK_MAX/1048576))MB)"

cat > /etc/security/limits.d/99-hysteria.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

# ======================================================= 2) المستخدم والشهادة
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
# المجلد يبقى ملكاً لـ root ومقروءاً لمجموعة hysteria فقط.
# لو كان المجلد مملوكاً لمستخدم الخدمة لأمكنه استبدال firewall.sh الذي يعمل بصلاحيات root.
chown root:hysteria "$HY_DIR" "$HY_DIR/server.key" "$HY_DIR/server.crt"
chmod 750 "$HY_DIR"
chmod 640 "$HY_DIR/server.key"
chmod 644 "$HY_DIR/server.crt"
CERT_PIN=$(openssl x509 -in "$HY_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)

# =========================================================== 3) ملف الإعداد
write_config() {
    local major="$1"
    if [ "$major" -eq 2 ]; then
        CFG="$HY_DIR/config.yaml"
        rm -f "$HY_DIR/config.json"
        {
            echo "listen: :${LISTEN_PORT}"
            echo
            echo "tls:"
            echo "  cert: ${HY_DIR}/server.crt"
            echo "  key: ${HY_DIR}/server.key"
            echo
            if [ "$ENABLE_OBFS" = "1" ]; then
                echo "obfs:"
                echo "  type: salamander"
                echo "  salamander:"
                echo "    password: $(yq "$OBFS_PASS")"
                echo
            fi
            echo "auth:"
            echo "  type: password"
            echo "  password: $(yq "$PASSWORD")"
            echo
            echo "quic:"
            echo "  initStreamReceiveWindow: ${STREAM_WIN}"
            echo "  maxStreamReceiveWindow: ${STREAM_WIN}"
            echo "  initConnReceiveWindow: ${CONN_WIN}"
            echo "  maxConnReceiveWindow: ${CONN_WIN}"
            echo "  maxIdleTimeout: 30s"
            echo "  maxIncomingStreams: ${STREAMS}"
            echo "  keepAlivePeriod: 10s"
            echo "  disablePathMTUDiscovery: false"
            echo
            if [ "$IGNORE_CLIENT_BW" = "1" ]; then
                echo "# BBR للجميع: يوزّع النطاق بعدالة ويمنع انهيار الشبكة مع تزايد المستخدمين"
                echo "ignoreClientBandwidth: true"
            else
                echo "bandwidth:"
                echo "  up: ${UP_MBPS} mbps"
                echo "  down: ${DOWN_MBPS} mbps"
                echo "ignoreClientBandwidth: false"
            fi
            echo
            echo "disableUDP: false"
            echo "udpIdleTimeout: 60s"
            echo
            echo "masquerade:"
            echo "  type: proxy"
            echo "  proxy:"
            echo "    url: $(yq "$MASQ_URL")"
            echo "    rewriteHost: true"
        } > "$CFG"
    else
        CFG="$HY_DIR/config.json"
        rm -f "$HY_DIR/config.yaml"
        local obfs_line=""
        if [ "$ENABLE_OBFS" = "1" ]; then obfs_line="\"obfs\": $(jq_ "$OBFS_PASS"),"; fi
        cat > "$CFG" <<EOF
{
    "listen": ":${LISTEN_PORT}",
    "cert": "${HY_DIR}/server.crt",
    "key": "${HY_DIR}/server.key",
    ${obfs_line}
    "auth": { "mode": "password", "config": { "password": $(jq_ "$PASSWORD") } },
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS},
    "disable_udp": false,
    "recv_window_conn": ${CONN_WIN},
    "recv_window_client": $(( CONN_WIN * 4 )),
    "max_conn_client": ${STREAMS},
    "disable_mtu_discovery": false
}
EOF
    fi
    chown root:hysteria "$CFG"
    chmod 640 "$CFG"
}

log "كتابة ملف الإعداد المناسب للإصدار v${HY_MAJOR}..."
STAMP=$(date +%s)
if [ -f "$HY_DIR/config.json" ]; then cp -a "$HY_DIR/config.json" "$HY_DIR/config.json.bak.$STAMP"; fi
if [ -f "$HY_DIR/config.yaml" ]; then cp -a "$HY_DIR/config.yaml" "$HY_DIR/config.yaml.bak.$STAMP"; fi
write_config "$HY_MAJOR"
ok "تم إنشاء $CFG"

# ======================================================== 4) الجدار الناري
log "إعادة بناء قواعد الجدار الناري بشكل آمن..."

cat > "$HY_DIR/firewall.sh" <<EOFW
#!/usr/bin/env bash
# قواعد Hysteria — تستخدم سلاسل مخصصة ولا تمسح قواعد الخدمات الأخرى
set -uo pipefail
LISTEN_PORT="${LISTEN_PORT}"
HOP_START="${HOP_START}"
HOP_END="${HOP_END}"
ENABLE_HOP="${ENABLE_HOP}"
IFACE="${IFACE}"

# --- حذف القواعد الخطيرة القديمة (REDIRECT على كامل المنافذ 1:65535) ---
while read -r spec; do
    [ -z "\$spec" ] && continue
    # shellcheck disable=SC2086
    iptables -t nat -D PREROUTING \${spec#-A PREROUTING } 2>/dev/null || true
done < <(iptables-save -t nat 2>/dev/null | grep -E '^-A PREROUTING .*(dport 1:65535|dports 1:65535)' || true)

# حذف قاعدة السماح المفتوحة لكل UDP
while iptables -C INPUT -p udp -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp -j ACCEPT 2>/dev/null || break
done

# --- سلسلة NAT مخصصة لقفز المنافذ ---
iptables -t nat -N HY_HOP 2>/dev/null || true
iptables -t nat -F HY_HOP
iptables -t nat -C PREROUTING -j HY_HOP 2>/dev/null || iptables -t nat -I PREROUTING 1 -j HY_HOP
if [ "\$ENABLE_HOP" = "1" ]; then
    iptables -t nat -A HY_HOP -i "\$IFACE" -p udp --dport "\$HOP_START":"\$HOP_END" \\
        -j REDIRECT --to-ports "\$LISTEN_PORT"
fi

# --- سلسلة السماح في INPUT (بدون مسح قواعد النظام) ---
iptables -N HY_IN 2>/dev/null || true
iptables -F HY_IN
iptables -C INPUT -j HY_IN 2>/dev/null || iptables -I INPUT 1 -j HY_IN
iptables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT
if [ "\$ENABLE_HOP" = "1" ]; then
    iptables -A HY_IN -p udp --dport "\$HOP_START":"\$HOP_END" -j ACCEPT
fi

# --- تعطيل تتبّع الاتصالات للمنفذ الأساسي عند إيقاف القفز ---
# يمنع امتلاء جدول conntrack مع آلاف المستخدمين.
# لا يُفعَّل مع القفز لأن NAT العكسي يحتاج إلى conntrack.
iptables -t raw -N HY_RAW 2>/dev/null || true
iptables -t raw -F HY_RAW
iptables -t raw -C PREROUTING -j HY_RAW 2>/dev/null || iptables -t raw -I PREROUTING 1 -j HY_RAW
iptables -t raw -D OUTPUT -p udp --sport "\$LISTEN_PORT" -j NOTRACK 2>/dev/null || true
if [ "\$ENABLE_HOP" != "1" ]; then
    iptables -t raw -A HY_RAW -p udp --dport "\$LISTEN_PORT" -j NOTRACK
    iptables -t raw -I OUTPUT 1 -p udp --sport "\$LISTEN_PORT" -j NOTRACK
fi

# --- IPv6 (يُتجاهل الخطأ إن لم يكن مفعّلاً) ---
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY_IN 2>/dev/null || true
    ip6tables -F HY_IN 2>/dev/null || true
    ip6tables -C INPUT -j HY_IN 2>/dev/null || ip6tables -I INPUT 1 -j HY_IN 2>/dev/null || true
    ip6tables -A HY_IN -p udp --dport "\$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
    if [ "\$ENABLE_HOP" = "1" ]; then
        ip6tables -A HY_IN -p udp --dport "\$HOP_START":"\$HOP_END" -j ACCEPT 2>/dev/null || true
        ip6tables -t nat -N HY_HOP 2>/dev/null || true
        ip6tables -t nat -F HY_HOP 2>/dev/null || true
        ip6tables -t nat -C PREROUTING -j HY_HOP 2>/dev/null || ip6tables -t nat -I PREROUTING 1 -j HY_HOP 2>/dev/null || true
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
    ok "قواعد الجدار الناري جاهزة (نطاق القفز ${HOP_START}-${HOP_END} ← ${LISTEN_PORT})"
else
    ok "قواعد الجدار الناري جاهزة (منفذ واحد: ${LISTEN_PORT} مع NOTRACK)"
fi

# وحدة تُعيد تطبيق القواعد بعد كل إقلاع (كانت مفقودة رغم الإشارة إليها)
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

# ======================================================== 5) خدمة systemd
log "تحديث وحدة systemd..."
write_unit() {
cat > "/etc/systemd/system/${SVC}.service" <<EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet)
Documentation=https://v2.hysteria.network/
After=network-online.target hysteria-firewall.service
Wants=network-online.target hysteria-firewall.service
# إلغاء حد محاولات إعادة التشغيل — كان يوقف الخدمة نهائياً بعد 5 محاولات فاشلة
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=hysteria
Group=hysteria
WorkingDirectory=${HY_DIR}
ExecStart=${HY_BIN} server --config ${CFG}
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
ReadWritePaths=${HY_DIR}

[Install]
WantedBy=multi-user.target
EOF
}
write_unit
systemctl daemon-reload
systemctl enable hysteria-firewall.service >/dev/null 2>&1 || true
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC" || true

# ========================================================= 6) أداة الفحص
cat > /usr/local/bin/hy-status <<EOF
#!/usr/bin/env bash
echo "== حالة الخدمة =="
systemctl --no-pager -l status ${SVC} | head -12
echo
echo "== منفذ الاستماع =="
ss -lunp 2>/dev/null | grep -E ":${LISTEN_PORT}[[:space:]]" || echo "لا يوجد استماع على ${LISTEN_PORT}!"
echo
echo "== الاتصالات المتتبَّعة =="
echo "الحالي: \$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -)"
echo "الأقصى: \$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -)"
echo
echo "== أخطاء استقبال UDP (يجب أن تبقى شبه ثابتة) =="
netstat -su 2>/dev/null | grep -iE 'receive errors|RcvbufErrors' || echo "netstat غير مثبت"
echo
echo "== آخر 15 سطر من السجل =="
journalctl -u ${SVC} -n 15 --no-pager
EOF
chmod +x /usr/local/bin/hy-status

# ==================================================== 7) التحقق النهائي
service_healthy() {
    systemctl is-active --quiet "$SVC" \
        && ss -lunp 2>/dev/null | grep -qE ":${LISTEN_PORT}[[:space:]]"
}

log "التحقق من استقرار الخدمة (10 ثوانٍ)..."
sleep 10

# إذا فشل الإصدار المُخمَّن، جرّب الصيغة الأخرى تلقائياً
if ! service_healthy && [ "$VER_KNOWN" -eq 0 ]; then
    warn "فشل التشغيل بصيغة v2 — إعادة المحاولة بصيغة v1..."
    HY_MAJOR=1
    write_config 1
    write_unit
    systemctl daemon-reload
    systemctl restart "$SVC" || true
    sleep 8
fi

echo
if service_healthy; then
    RESTARTS=$(systemctl show -p NRestarts --value "$SVC" 2>/dev/null || echo 0)
    ok "الخدمة تعمل بثبات (مرات إعادة التشغيل: ${RESTARTS})"
    echo
    echo "──────────────── بيانات الاتصال ────────────────"
    echo " الخادم        : ${PUBIP:-<ضع IP السيرفر>}"
    echo " المنفذ        : ${LISTEN_PORT}"
    if [ "$ENABLE_HOP" = "1" ]; then echo " نطاق القفز    : ${HOP_START}-${HOP_END}"; fi
    echo " كلمة المرور   : ${PASSWORD}"
    if [ "$ENABLE_OBFS" = "1" ]; then echo " التمويه       : salamander / ${OBFS_PASS}"; fi
    echo " SNI           : ${SNI}  (فعّل insecure — الشهادة ذاتية التوقيع)"
    if [ -n "${CERT_PIN:-}" ]; then echo " بصمة الشهادة  : ${CERT_PIN}"; fi
    if [ "$HY_MAJOR" -eq 2 ]; then
        Q="insecure=1&sni=${SNI}"
        if [ "$ENABLE_OBFS" = "1" ]; then Q="${Q}&obfs=salamander&obfs-password=${OBFS_PASS}"; fi
        if [ "$ENABLE_HOP" = "1" ];  then Q="${Q}&mport=${HOP_START}-${HOP_END}"; fi
        echo
        echo " رابط جاهز للتطبيق:"
        echo " hy2://${PASSWORD}@${PUBIP:-SERVER_IP}:${LISTEN_PORT}/?${Q}#MinaProNet"
    fi
    echo "────────────────────────────────────────────────"
    echo
    echo " للفحص في أي وقت:  hy-status"
else
    warn "الخدمة لم تستقر. مخرجات السجل:"
    journalctl -u "$SVC" -n 30 --no-pager || true
    echo
    echo "تحقّق من: تطابق إصدار hysteria مع صيغة الإعداد، صلاحيات الشهادة، وتعارض المنفذ."
    exit 1
fi
