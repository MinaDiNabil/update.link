#!/usr/bin/env bash
# ==============================================================================
#  MinaProNet VPN — إصلاح  sendto: operation not permitted
#
#  تقدّم مؤكَّد: إصلاح udpgw نجح. السجل صار يعرض وجهات حقيقية
#  (142.250.129.156 لجوجل وغيرها) بدل 127.0.0.1:7300 فقط.
#
#  العطل المتبقي:
#     write udp [::]:36712->CLIENT: sendto: operation not permitted
#  EPERM على sendto تعني أن netfilter أسقط الحزمة الصادرة، فالرد
#  لا يغادر السيرفر أصلاً.
#
#  السبب المرجَّح — وهو من صنعي:
#  ردود hysteria تحتاج ترجمة NAT عكسية (36712 ← منفذ القفز) مخزّنة
#  في سجل conntrack. فرضتُ على حركة القفز مهلة 5/8 ثوانٍ، فينتهي
#  عمر السجل بينما اتصال QUIC حي، فيُنشأ سجل ثانٍ زوج ذهابه مطابق
#  لزوج عودة الأول ⇒ تصادم ⇒ NF_DROP ⇒ EPERM.
#
#  هذا السكربت يقيس أولاً (عدّاد insert_failed) ثم يصلح ثم يعيد
#  القياس، فلا يعتمد على الظن.
#
#  الاستخدام:  sudo bash fix-eperm.sh
# ==============================================================================

set -Eeuo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:$PATH"

SVC="hysteria-server"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-multiuser.conf"
FW="/etc/hysteria/firewall.sh"
MEASURE="${MEASURE:-20}"      # مدة القياس بالثواني

log()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }
P()    { printf '  %-40s %s\n' "$1" "$2"; }

[ "$(id -u)" -eq 0 ] || die "يجب تشغيل السكربت بصلاحيات root."

# جمع عمود سداسي عشري من /proc/net/stat/nf_conntrack حسب اسمه
ct_stat() {
    local col total=0 v
    [ -r /proc/net/stat/nf_conntrack ] || { echo 0; return; }
    col=$(awk -v n="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==n){print i; exit}}' /proc/net/stat/nf_conntrack)
    [ -n "$col" ] || { echo 0; return; }
    while read -r v; do
        [ -z "$v" ] && continue
        case "$v" in *[!0-9a-fA-F]*) continue;; esac
        total=$(( total + 16#$v ))
    done < <(awk -v c="$col" 'NR>1{print $c}' /proc/net/stat/nf_conntrack)
    echo "$total"
}

# ==================== ١) القياس قبل الإصلاح ====================
echo "════════════ القياس قبل الإصلاح (${MEASURE} ثانية) ════════════"
IF0=$(ct_stat insert_failed); DR0=$(ct_stat drop)
P "insert_failed الآن:" "$IF0"
P "drop الآن:" "$DR0"
P "conntrack مستخدم/أقصى:" "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -)/$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -)"
P "مهلة UDP:" "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null || echo -)s / $(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream 2>/dev/null || echo -)s"

echo
echo "  سياسات المهلة القصيرة المطبَّقة:"
if iptables -t raw -S HY_RAW 2>/dev/null | grep -q 'CT --timeout'; then
    echo "    ✔ قاعدة CT في جدول raw (nfct)"
fi
if nft list table ip hyhop >/dev/null 2>&1; then
    echo "    ✔ جدول nftables باسم hyhop"
fi

echo
echo "  قواعد إسقاط محتملة في OUTPUT:"
iptables -L OUTPUT -n -v 2>/dev/null | awk 'NR>2 && ($3=="DROP"||$3=="REJECT")' | sed 's/^/    /' || true
iptables -L OUTPUT -n -v 2>/dev/null | head -2 | sed 's/^/    /' || true

echo
echo "  رسائل النواة عن conntrack:"
dmesg 2>/dev/null | grep -i 'nf_conntrack.*table full' | tail -3 | sed 's/^/    /' || echo "    لا شيء"

log "قياس معدل الفشل خلال ${MEASURE} ثانية... (اترك مستخدماً متصلاً)"
sleep "$MEASURE"
IF1=$(ct_stat insert_failed); DR1=$(ct_stat drop)
DIF=$(( IF1 - IF0 )); DDR=$(( DR1 - DR0 ))
echo
P "ارتفاع insert_failed:" "$DIF"
P "ارتفاع drop:" "$DDR"
if [ "$DIF" -gt 0 ]; then
    warn "تأكد التصادم: ${DIF} فشل إدراج خلال ${MEASURE} ثانية."
    warn "هذا هو مصدر operation not permitted."
else
    warn "لم يرتفع insert_failed. السبب قد يكون قاعدة إسقاط في OUTPUT."
    warn "سيُطبَّق الإصلاح على أي حال ثم يُعاد القياس."
fi

# ==================== ٢) الإصلاح ====================
echo
echo "════════════ تطبيق الإصلاح ════════════"

# إزالة سياسات المهلة القصيرة التي سببت انتهاء ترجمة NAT مبكراً
log "إزالة سياسات المهلة القصيرة..."
nft delete table ip hyhop >/dev/null 2>&1 || true
iptables -t raw -F HY_RAW >/dev/null 2>&1 || true
if command -v nfct >/dev/null 2>&1; then
    nfct timeout delete hyhop >/dev/null 2>&1 || true
fi
# منع إعادة إضافتها عند الإقلاع دون المساس بنطاق القفز
if [ -f "$FW" ]; then
    sed -i 's/^HOP_CT_MODE=.*/HOP_CT_MODE="0"/' "$FW"
    ok "عُطِّلت السياسة في ${FW} مع بقاء نطاق القفز كما هو"
fi

# مهلة سخية تبقي ترجمة NAT حيّة طوال عمر اتصال QUIC
log "ضبط مهل conntrack..."
RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
CT_MAX=$(( RAM_MB * 256 ))
[ "$CT_MAX" -gt 2097152 ] && CT_MAX=2097152
[ "$CT_MAX" -lt 262144 ]  && CT_MAX=262144
CT_BUCKETS=$(( CT_MAX / 4 ))
if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$CT_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi

sysctl -w net.netfilter.nf_conntrack_udp_timeout=120 >/dev/null 2>&1 || true
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=300 >/dev/null 2>&1 || true
sysctl -w net.netfilter.nf_conntrack_max="$CT_MAX" >/dev/null 2>&1 || true

if [ -f "$SYSCTL_FILE" ]; then
    sed -i "s/^net.netfilter.nf_conntrack_udp_timeout = .*/net.netfilter.nf_conntrack_udp_timeout = 120/" "$SYSCTL_FILE"
    sed -i "s/^net.netfilter.nf_conntrack_udp_timeout_stream = .*/net.netfilter.nf_conntrack_udp_timeout_stream = 300/" "$SYSCTL_FILE"
    sed -i "s/^net.netfilter.nf_conntrack_max = .*/net.netfilter.nf_conntrack_max = ${CT_MAX}/" "$SYSCTL_FILE"
else
    cat > "$SYSCTL_FILE" <<EOF
net.netfilter.nf_conntrack_udp_timeout = 120
net.netfilter.nf_conntrack_udp_timeout_stream = 300
net.netfilter.nf_conntrack_max = ${CT_MAX}
EOF
fi
ok "المهل: 120s / 300s | conntrack_max: ${CT_MAX}"

# تنظيف السجلات العالقة حتى تبدأ الترجمات من جديد
if command -v conntrack >/dev/null 2>&1; then
    conntrack -D -p udp >/dev/null 2>&1 || true
    ok "مُسحت سجلات UDP القديمة"
fi

# ==================== ٣) تشغيل الخدمات ====================
if systemctl list-unit-files 2>/dev/null | grep -q badvpn-udpgw; then
    systemctl is-active --quiet badvpn-udpgw.service || systemctl start badvpn-udpgw.service >/dev/null 2>&1 || true
fi
log "إعادة تشغيل hysteria..."
systemctl reset-failed "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC" >/dev/null 2>&1 || systemctl start "$SVC" >/dev/null 2>&1 || true
sleep 5
if systemctl is-active --quiet "$SVC"; then
    ok "خدمة hysteria تعمل"
else
    warn "خدمة hysteria متوقفة:"
    journalctl -u "$SVC" -n 15 --no-pager | sed 's/^/    /' || true
fi

# ==================== ٤) القياس بعد الإصلاح ====================
echo
echo "════════════ القياس بعد الإصلاح (${MEASURE} ثانية) ════════════"
log "اطلب من مستخدم أن يتصل ويتصفح الآن..."
IF2=$(ct_stat insert_failed); DR2=$(ct_stat drop)
sleep "$MEASURE"
IF3=$(ct_stat insert_failed); DR3=$(ct_stat drop)
DIF2=$(( IF3 - IF2 )); DDR2=$(( DR3 - DR2 ))
P "ارتفاع insert_failed:" "$DIF2   (كان ${DIF})"
P "ارتفاع drop:" "$DDR2   (كان ${DDR})"

echo
echo "  أخطاء EPERM في آخر ${MEASURE} ثانية:"
EP=$(journalctl -u "$SVC" --since "${MEASURE} seconds ago" --no-pager 2>/dev/null \
     | grep -c 'operation not permitted' || true)
P "عددها:" "${EP:-0}"

echo
if [ "${EP:-0}" = "0" ] && [ "$DIF2" -le 0 ]; then
    echo "════════════════════════════════════════════════════"
    echo " اختفى الخطأ. جرّب التصفح من التطبيق الآن."
    echo "════════════════════════════════════════════════════"
else
    warn "ما زال الخطأ موجوداً. أرسل لي مخرجات هذه الأوامر:"
    echo
    echo "  iptables -L OUTPUT -n -v --line-numbers | head -30"
    echo "  iptables -t nat -L POSTROUTING -n -v | head -20"
    echo "  nft list ruleset | head -60"
    echo "  journalctl -u ${SVC} -n 20 --no-pager"
    echo
    echo "الحالة الحالية:"
    echo "--- filter OUTPUT ---"
    iptables -L OUTPUT -n -v --line-numbers 2>/dev/null | head -20 | sed 's/^/  /' || true
    echo "--- nat POSTROUTING ---"
    iptables -t nat -L POSTROUTING -n -v 2>/dev/null | head -12 | sed 's/^/  /' || true
    echo "--- nft ruleset (أسماء الجداول) ---"
    nft list tables 2>/dev/null | sed 's/^/  /' || echo "  لا يوجد"
fi

echo
echo " للمراقبة المباشرة:  journalctl -u ${SVC} -f"
