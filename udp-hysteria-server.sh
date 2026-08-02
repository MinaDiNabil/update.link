#!/usr/bin/env bash
# ============================================================
#  MinaProNet VPN - Hysteria UDP Server Setup  (Hardened v2)
#  Compatible with MinaProNetVPN Tunnel App (Hysteria v1)
#  Ubuntu 20.04 / 22.04 / 24.04
# ============================================================
#  ما الذي تغيّر ولماذا (أسباب حظر OVH في النسخة القديمة):
#   1) المدى 1-65535 + REDIRECT لكل UDP  -> السيرفر يردّ على أي
#      منفذ = يبدو كـ UDP flood / port-scan sink أمام VAC، ويكشف
#      كل خدمات UDP المحلية (53/123/161...) للإنترنت.
#      الحل: مدى ضيّق مسموح (<= 1000 منفذ، 20000-60000 فقط).
#   2) ip_forward=1 + غياب أي ضبط خروج -> العميل يستطيع إطلاق
#      DDoS/amplification/spam من السيرفر = بلاغ إساءة فوري.
#      الحل: ip_forward=0 + سلسلة OUTPUT مقيّدة لمستخدم hysteria.
#   3) iptables -I INPUT ... ACCEPT في الأعلى + flush لـ PREROUTING
#      -> تعطيل الجدار الناري الحالي وكسر قواعد خدمات أخرى.
#      الحل: سلاسل مخصّصة، بدون flush، وبدون ACCEPT شامل.
#  إضافات: rp_filter، تحديد معدّل ICMP unreachable، حدود معدّل
#  لكل وجهة، خدمة حراسة (guard) توقف النفق عند فيضان صادر.
# ============================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_VER="v1.3.5"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="${HYSTERIA_DIR}/config.json"
HYSTERIA_CERT="${HYSTERIA_DIR}/server.crt"
HYSTERIA_KEY="${HYSTERIA_DIR}/server.key"
HYSTERIA_USER="hysteria"
SVC_MAIN="/etc/systemd/system/hysteria-server.service"
SVC_FW="/etc/systemd/system/hysteria-firewall.service"
SVC_GUARD="/etc/systemd/system/hysteria-guard.service"
FW_SCRIPT="${HYSTERIA_DIR}/firewall.sh"
GUARD_SCRIPT="/usr/local/sbin/hysteria-guard.sh"
SYSCTL_FILE="/etc/sysctl.d/99-hysteria-udp.conf"

# --- حدود الأمان (عدّلها بوعي) ---------------------------------
HOP_MIN_PORT=20000          # لا نسمح بمنافذ نظام معروفة
HOP_MAX_PORT=60000
HOP_MAX_SIZE=1000           # أقصى عدد منافذ في المدى
GUARD_MAX_MBPS=350          # فيضان صادر مستمر -> إيقاف مؤقت
GUARD_MAX_PPS=120000
GUARD_STRIKES=3             # عدد عينات (10ث لكل عينة) قبل الإيقاف
GUARD_COOLDOWN=900          # ثوانٍ قبل إعادة التشغيل التلقائي
# منافذ ممنوع استخدامها كمنفذ استماع (خدمات/تضخيم)
FORBIDDEN_PORTS="17 19 53 67 68 69 111 123 137 138 161 162 389 500 514 520 623 1194 1434 1701 1900 3283 3702 4500 5093 5351 5353 10001 11211 27015 30718 32414 33848 37810"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   MinaProNet VPN - Hysteria UDP (Hardened v2)    ║"
    echo "║      Abuse-safe config for OVH / any host        ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}
msg()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

check_root() {
    [ "$(id -u)" -eq 0 ] || { err "Must run as root (sudo)"; exit 1; }
}

detect_iface() {
    IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [ -n "${IFACE:-}" ] || IFACE=$(ls /sys/class/net | grep -v '^lo$' | head -n1)
    info "Main interface: ${IFACE}"
}

get_server_ip() {
    SERVER_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "${SERVER_IP:-}" ]; then
        SERVER_IP=$(curl -s4m5 https://ifconfig.me 2>/dev/null || true)
    fi
    [ -n "${SERVER_IP:-}" ] || read -rp "Enter your server IP: " SERVER_IP
    msg "Server IP: ${SERVER_IP}"
}

install_deps() {
    info "Installing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl wget openssl ca-certificates iptables \
        iptables-persistent conntrack iproute2 >/dev/null 2>&1
    msg "Dependencies installed"
}

install_hysteria() {
    local ARCH TMP
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) err "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    info "Downloading Hysteria ${HYSTERIA_VER} (${ARCH})..."
    TMP=$(mktemp)
    if ! wget -q --show-progress -O "$TMP" \
        "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${ARCH}"; then
        err "Download failed"; rm -f "$TMP"; exit 1
    fi

    # تحقّق من سلامة الملف قبل التثبيت (بدل الكتابة المباشرة فوق المسار)
    if ! head -c4 "$TMP" | grep -q $'\x7fELF'; then
        err "Downloaded file is not a valid binary"; rm -f "$TMP"; exit 1
    fi
    if [ -n "${HYSTERIA_SHA256:-}" ]; then
        echo "${HYSTERIA_SHA256}  ${TMP}" | sha256sum -c - >/dev/null 2>&1 \
            || { err "SHA256 mismatch"; rm -f "$TMP"; exit 1; }
        msg "SHA256 verified"
    else
        warn "No HYSTERIA_SHA256 provided — skipping checksum verification"
    fi
    chmod 755 "$TMP"; mv -f "$TMP" "$HYSTERIA_BIN"
    "$HYSTERIA_BIN" version >/dev/null 2>&1 || warn "Binary did not report a version"
    msg "Hysteria installed at ${HYSTERIA_BIN}"
}

create_user() {
    if ! id "$HYSTERIA_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$HYSTERIA_USER"
    fi
    HY_UID=$(id -u "$HYSTERIA_USER")
    msg "Service user: ${HYSTERIA_USER} (uid ${HY_UID})"
}

generate_cert() {
    mkdir -p "$HYSTERIA_DIR"; chmod 750 "$HYSTERIA_DIR"
    if [ -f "$HYSTERIA_CERT" ] && [ -f "$HYSTERIA_KEY" ]; then
        warn "Certificate exists, skipping"; return
    fi
    info "Generating self-signed certificate..."
    # ملاحظة: لا نستخدم اسم نطاق لا نملكه (مثل bing.com) — هذا انتحال هوية
    # ويُعرّضك لبلاغات. استخدم نطاقك أو اسم محايد.
    local CN="${CERT_CN:-hysteria.local}"
    openssl ecparam -genkey -name prime256v1 -out "$HYSTERIA_KEY" 2>/dev/null
    openssl req -new -x509 -key "$HYSTERIA_KEY" -out "$HYSTERIA_CERT" \
        -subj "/CN=${CN}" -days 3650 2>/dev/null
    chmod 640 "$HYSTERIA_KEY"; chmod 644 "$HYSTERIA_CERT"
    chown root:"$HYSTERIA_USER" "$HYSTERIA_KEY" "$HYSTERIA_CERT"
    msg "Certificate generated (CN=${CN})"
}

port_in_use() {
    ss -ulnH "sport = :$1" 2>/dev/null | grep -q . && return 0 || return 1
}

validate_single_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || return 1
    for f in $FORBIDDEN_PORTS; do
        [ "$p" = "$f" ] && { err "Port $p is a well-known service/amplification port — refused."; return 1; }
    done
    if port_in_use "$p"; then
        err "UDP port $p is already used by another service:"
        ss -ulnp "sport = :$p" 2>/dev/null | tail -n +2
        return 1
    fi
    return 0
}

get_config() {
    echo ""; echo -e "${BOLD}=== Server Configuration ===${NC}"; echo ""
    echo -e "${CYAN}Port hopping range must be inside ${HOP_MIN_PORT}-${HOP_MAX_PORT}"
    echo -e "and at most ${HOP_MAX_SIZE} ports wide (this is what keeps OVH happy).${NC}"
    echo -e "${CYAN}Examples: 36712   |   40000-40500${NC}"

    while true; do
        read -rp "$(echo -e "${CYAN}Enter port or range [default: 40000-40200]: ${NC}")" PORT_INPUT
        PORT_INPUT=${PORT_INPUT:-40000-40200}

        if [[ "$PORT_INPUT" == *"-"* ]]; then
            PORT_RANGE_START=${PORT_INPUT%%-*}
            PORT_RANGE_END=${PORT_INPUT##*-}
            if ! [[ "$PORT_RANGE_START" =~ ^[0-9]+$ && "$PORT_RANGE_END" =~ ^[0-9]+$ ]]; then
                err "Invalid range."; continue
            fi
            if [ "$PORT_RANGE_START" -ge "$PORT_RANGE_END" ]; then
                err "Start must be lower than end."; continue
            fi
            if [ "$PORT_RANGE_START" -lt "$HOP_MIN_PORT" ] || [ "$PORT_RANGE_END" -gt "$HOP_MAX_PORT" ]; then
                err "Range must stay within ${HOP_MIN_PORT}-${HOP_MAX_PORT}."
                warn "Ranges like 1-65535 are exactly what got the server null-routed."
                continue
            fi
            if [ $((PORT_RANGE_END - PORT_RANGE_START + 1)) -gt "$HOP_MAX_SIZE" ]; then
                err "Range too wide (max ${HOP_MAX_SIZE} ports)."; continue
            fi
            # لا نسمح بمدى يبتلع منفذًا مستخدمًا بالفعل
            local busy=""
            while read -r p; do
                [ -n "$p" ] || continue
                if [ "$p" -ge "$PORT_RANGE_START" ] && [ "$p" -le "$PORT_RANGE_END" ]; then busy="$busy $p"; fi
            done < <(ss -ulnH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -u)
            if [ -n "$busy" ]; then
                err "These UDP ports inside the range are already in use:${busy}"; continue
            fi
            LISTEN_PORT="$PORT_RANGE_START"
            REDIR_START=$((PORT_RANGE_START + 1))
            REDIR_END="$PORT_RANGE_END"
            USE_PORT_HOPPING=true
            info "Port hopping: ${PORT_RANGE_START}-${PORT_RANGE_END} (listen on ${LISTEN_PORT})"
            break
        else
            if validate_single_port "$PORT_INPUT"; then
                LISTEN_PORT="$PORT_INPUT"; USE_PORT_HOPPING=false
                info "Single port: ${LISTEN_PORT}"
                break
            fi
        fi
    done

    read -rp "$(echo -e "${CYAN}Obfs password [default: random]: ${NC}")" OBFS
    OBFS=${OBFS:-$(openssl rand -hex 12)}
    read -rp "$(echo -e "${CYAN}Auth password [default: random]: ${NC}")" AUTH_STR
    AUTH_STR=${AUTH_STR:-$(openssl rand -hex 16)}

    read -rp "$(echo -e "${CYAN}Max Upload Mbps per client [default: 50]: ${NC}")" UP_MBPS
    UP_MBPS=${UP_MBPS:-50}
    read -rp "$(echo -e "${CYAN}Max Download Mbps per client [default: 50]: ${NC}")" DOWN_MBPS
    DOWN_MBPS=${DOWN_MBPS:-50}

    read -rp "$(echo -e "${CYAN}Disable UDP relay for clients? (safest vs DDoS abuse) [y/N]: ${NC}")" NOUDP
    [[ "${NOUDP,,}" == "y" ]] && DISABLE_UDP=true || DISABLE_UDP=false

    read -rp "$(echo -e "${CYAN}Enable outbound flood guard (auto-stop on abuse)? [Y/n]: ${NC}")" GUARD
    [[ "${GUARD,,}" == "n" ]] && USE_GUARD=false || USE_GUARD=true
    echo ""
}

create_config() {
    info "Creating configuration..."
    cat > "$HYSTERIA_CONFIG" << EOF
{
    "listen": ":${LISTEN_PORT}",
    "cert": "${HYSTERIA_CERT}",
    "key": "${HYSTERIA_KEY}",
    "obfs": "${OBFS}",
    "auth": {
        "mode": "password",
        "config": { "password": "${AUTH_STR}" }
    },
    "up_mbps": ${UP_MBPS},
    "down_mbps": ${DOWN_MBPS},
    "disable_udp": ${DISABLE_UDP},
    "recv_window_conn": 5767168,
    "recv_window_client": 23068672,
    "max_conn_client": 128
}
EOF
    chmod 640 "$HYSTERIA_CONFIG"; chown root:"$HYSTERIA_USER" "$HYSTERIA_CONFIG"
    msg "Configuration created"
}

apply_sysctl() {
    info "Applying kernel settings..."
    modprobe nf_conntrack 2>/dev/null || true
    modprobe nf_nat 2>/dev/null || true

    cat > "$SYSCTL_FILE" << 'EOF'
# --- Hysteria UDP tuning (abuse-safe) ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384

# لا نحتاج توجيه حزم: Hysteria يمرّر في user-space.
# ip_forward=1 يحوّل السيرفر إلى موجّه مفتوح = سبب حظر مباشر.
net.ipv4.ip_forward = 0

# منع الحزم المزوّرة (anti-spoofing) — أهم ضابط ضد بلاغات الإساءة
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# تحديد معدّل ICMP unreachable (يمنع فيضان ICMP صادر عند توقّف الخدمة)
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Conntrack مضبوط على مدى منافذ صغير
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120

net.ipv4.tcp_syncookies = 1
EOF
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
        msg "BBR enabled"
    fi
    msg "Kernel settings applied"
}

# ============================================================
#  الجدار الناري: سلاسل مخصّصة فقط — لا flush ولا ACCEPT شامل
# ============================================================
write_firewall_script() {
    info "Writing firewall rules..."
    local HOP_RULES_V4="" HOP_RULES_V6="" IN_MATCH
    if [ "$USE_PORT_HOPPING" = true ]; then
        IN_MATCH="${LISTEN_PORT}:${PORT_RANGE_END}"
        HOP_RULES_V4="iptables -t nat -A HY-REDIR -i \"\$IFACE\" -p udp --dport ${REDIR_START}:${REDIR_END} -j REDIRECT --to-ports ${LISTEN_PORT}
add_once nat PREROUTING -i \"\$IFACE\" -p udp --dport ${REDIR_START}:${REDIR_END} -j HY-REDIR"
        HOP_RULES_V6="ip6tables -t nat -A HY-REDIR -i \"\$IFACE\" -p udp --dport ${REDIR_START}:${REDIR_END} -j REDIRECT --to-ports ${LISTEN_PORT} 2>/dev/null || true
add_once6 nat PREROUTING -i \"\$IFACE\" -p udp --dport ${REDIR_START}:${REDIR_END} -j HY-REDIR"
    else
        IN_MATCH="${LISTEN_PORT}"
    fi

    cat > "$FW_SCRIPT" << EOFW
#!/usr/bin/env bash
# Hysteria firewall — idempotent. لا يمسح قواعد أي خدمة أخرى.
IFACE="${IFACE}"
HY_UID="${HY_UID}"
LISTEN_PORT="${LISTEN_PORT}"
IN_MATCH="${IN_MATCH}"

mkchain() { # table chain
    iptables -t "\$1" -N "\$2" 2>/dev/null || iptables -t "\$1" -F "\$2"
}
mkchain6() {
    ip6tables -t "\$1" -N "\$2" 2>/dev/null || ip6tables -t "\$1" -F "\$2" 2>/dev/null
}
add_once() { # table chain-spec...
    local t="\$1"; shift
    iptables -t "\$t" -C "\$@" 2>/dev/null || iptables -t "\$t" -A "\$@"
}
add_once6() {
    local t="\$1"; shift
    ip6tables -t "\$t" -C "\$@" 2>/dev/null || ip6tables -t "\$t" -A "\$@" 2>/dev/null || true
}

modprobe nf_conntrack 2>/dev/null
modprobe nf_nat 2>/dev/null
modprobe xt_hashlimit 2>/dev/null

# ---------- 1) الوارد: قبول محدود المعدّل للمدى فقط ----------
mkchain filter HY-IN
iptables -A HY-IN -m conntrack --ctstate INVALID -j DROP
iptables -A HY-IN -m hashlimit --hashlimit-name hy_in --hashlimit-mode srcip \\
    --hashlimit-above 15000/sec --hashlimit-burst 20000 \\
    --hashlimit-htable-expire 60000 -j DROP 2>/dev/null \\
  || iptables -A HY-IN -m limit --limit 50000/sec -j RETURN 2>/dev/null
iptables -A HY-IN -j ACCEPT
add_once filter INPUT -i "\$IFACE" -p udp --dport \$IN_MATCH -j HY-IN

# ---------- 2) إعادة التوجيه (port hopping) ----------
mkchain nat HY-REDIR
${HOP_RULES_V4}

mkchain6 nat HY-REDIR
${HOP_RULES_V6}

# ---------- 3) الصادر من النفق: أهم جزء لمنع بلاغات OVH ----------
# كل ما يخرج باسم مستخدم hysteria يمرّ عبر HY-OUT
mkchain filter HY-OUT
iptables -A HY-OUT -o lo -j RETURN
# منع الوصول للشبكات الخاصة/الداخلية (منع الارتداد داخل شبكة المزوّد)
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 240.0.0.0/4; do
    iptables -A HY-OUT -d \$net -j REJECT --reject-with icmp-admin-prohibited
done
# منع السبام (بلاغ إساءة شائع جدًا)
iptables -A HY-OUT -p tcp -m multiport --dports 25,465,587 -j REJECT
# منع منافذ التضخيم المعروفة (reflection/amplification)
iptables -A HY-OUT -p udp -m multiport --dports 17,19,69,111,137,138,161,162,389,520,623,1434,1900,3283,3702 -j REJECT
iptables -A HY-OUT -p udp -m multiport --dports 5093,5351,5353,10001,11211,27015,30718,32414,33848,37810 -j REJECT
# تحديد معدّل DNS و NTP لكل وجهة (يمنع استخدام النفق في DNS flood)
iptables -A HY-OUT -p udp --dport 53 -m hashlimit --hashlimit-name hy_dns \\
    --hashlimit-mode dstip --hashlimit-above 200/sec --hashlimit-burst 400 -j DROP 2>/dev/null
iptables -A HY-OUT -p udp --dport 123 -m hashlimit --hashlimit-name hy_ntp \\
    --hashlimit-mode dstip --hashlimit-above 20/sec --hashlimit-burst 40 -j DROP 2>/dev/null
# سقف حزم لكل وجهة: الاستخدام العادي لا يقترب منه، الهجوم يتجاوزه فورًا
iptables -A HY-OUT -p udp -m hashlimit --hashlimit-name hy_udpflood \\
    --hashlimit-mode dstip --hashlimit-above 6000/sec --hashlimit-burst 12000 \\
    --hashlimit-htable-expire 60000 -j DROP 2>/dev/null
# منع فحص المنافذ من داخل النفق
iptables -A HY-OUT -p tcp --syn -m hashlimit --hashlimit-name hy_scan \\
    --hashlimit-mode srcip --hashlimit-above 300/sec --hashlimit-burst 600 -j DROP 2>/dev/null
iptables -A HY-OUT -j RETURN
add_once filter OUTPUT -m owner --uid-owner "\$HY_UID" -j HY-OUT

# نفس الحماية على IPv6
mkchain6 filter HY-OUT
ip6tables -A HY-OUT -o lo -j RETURN 2>/dev/null
ip6tables -A HY-OUT -d fc00::/7 -j REJECT 2>/dev/null
ip6tables -A HY-OUT -d fe80::/10 -j REJECT 2>/dev/null
ip6tables -A HY-OUT -p tcp -m multiport --dports 25,465,587 -j REJECT 2>/dev/null
ip6tables -A HY-OUT -p udp -m multiport --dports 17,19,69,111,137,138,161,162,389,520,623,1434,1900,3283,3702 -j REJECT 2>/dev/null
ip6tables -A HY-OUT -p udp -m multiport --dports 5093,5351,5353,10001,11211,27015,30718,32414,33848,37810 -j REJECT 2>/dev/null
ip6tables -A HY-OUT -j RETURN 2>/dev/null
add_once6 filter OUTPUT -m owner --uid-owner "\$HY_UID" -j HY-OUT

# ---------- 4) كبح ICMP unreachable الصادر ----------
mkchain filter HY-ICMP
iptables -A HY-ICMP -m limit --limit 5/sec --limit-burst 10 -j RETURN
iptables -A HY-ICMP -j DROP
add_once filter OUTPUT -p icmp --icmp-type port-unreachable -j HY-ICMP

# ---------- 5) حفظ ----------
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1
elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
fi
exit 0
EOFW
    chmod 750 "$FW_SCRIPT"
    bash "$FW_SCRIPT" && msg "Firewall rules applied" || err "Firewall script failed"
}

create_guard() {
    [ "$USE_GUARD" = true ] || { info "Flood guard disabled by user"; return; }
    cat > "$GUARD_SCRIPT" << EOFG
#!/usr/bin/env bash
# يوقف النفق مؤقتًا إذا خرج منه فيضان مستمر — يمنع null-route من المزوّد.
IFACE="${IFACE}"
MAX_MBPS=${GUARD_MAX_MBPS}
MAX_PPS=${GUARD_MAX_PPS}
STRIKES_MAX=${GUARD_STRIKES}
COOLDOWN=${GUARD_COOLDOWN}
strikes=0
while true; do
    b1=\$(cat /sys/class/net/\$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
    p1=\$(cat /sys/class/net/\$IFACE/statistics/tx_packets 2>/dev/null || echo 0)
    sleep 10
    b2=\$(cat /sys/class/net/\$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
    p2=\$(cat /sys/class/net/\$IFACE/statistics/tx_packets 2>/dev/null || echo 0)
    mbps=\$(( (b2 - b1) * 8 / 10 / 1000000 ))
    pps=\$(( (p2 - p1) / 10 ))
    if [ "\$mbps" -gt "\$MAX_MBPS" ] || [ "\$pps" -gt "\$MAX_PPS" ]; then
        strikes=\$((strikes + 1))
        logger -t hysteria-guard "high egress: \${mbps}Mbps \${pps}pps (strike \${strikes}/\${STRIKES_MAX})"
        if [ "\$strikes" -ge "\$STRIKES_MAX" ]; then
            logger -t hysteria-guard "THRESHOLD EXCEEDED — stopping hysteria-server for \${COOLDOWN}s"
            systemctl stop hysteria-server
            sleep "\$COOLDOWN"
            systemctl start hysteria-server
            logger -t hysteria-guard "hysteria-server restarted after cooldown"
            strikes=0
        fi
    else
        strikes=0
    fi
done
EOFG
    chmod 750 "$GUARD_SCRIPT"
    cat > "$SVC_GUARD" << EOF
[Unit]
Description=Hysteria outbound flood guard
After=hysteria-server.service

[Service]
Type=simple
ExecStart=${GUARD_SCRIPT}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    msg "Flood guard installed (${GUARD_MAX_MBPS} Mbps / ${GUARD_MAX_PPS} pps)"
}

create_services() {
    info "Creating systemd services..."
    cat > "$SVC_FW" << EOF
[Unit]
Description=Hysteria firewall rules
After=network-online.target
Wants=network-online.target
Before=hysteria-server.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${FW_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

    local CAPS=""
    if [ "$LISTEN_PORT" -lt 1024 ]; then
        CAPS=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
    else
        CAPS="CapabilityBoundingSet="
    fi

    cat > "$SVC_MAIN" << EOF
[Unit]
Description=Hysteria UDP Server (MinaProNet VPN)
After=network-online.target hysteria-firewall.service
Wants=network-online.target
Requires=hysteria-firewall.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${HYSTERIA_USER}
Group=${HYSTERIA_USER}
ExecStart=${HYSTERIA_BIN} server --config ${HYSTERIA_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
TasksMax=4096
NoNewPrivileges=yes
${CAPS}
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    msg "Services created"
}

start_services() {
    info "Starting services..."
    systemctl enable hysteria-firewall >/dev/null 2>&1
    systemctl restart hysteria-firewall
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    if [ "$USE_GUARD" = true ]; then
        systemctl enable hysteria-guard >/dev/null 2>&1
        systemctl restart hysteria-guard
    fi
    sleep 3
    if systemctl is-active --quiet hysteria-server; then
        msg "Hysteria server is RUNNING"
    else
        err "Failed to start. Logs:"
        journalctl -u hysteria-server --no-pager -n 25
        exit 1
    fi
}

verify_server() {
    echo ""; info "Verification"
    ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT}" \
        && msg "1/6 Listening on UDP ${LISTEN_PORT}" || err "1/6 NOT listening"

    [ "$(sysctl -n net.ipv4.ip_forward)" = "0" ] \
        && msg "2/6 ip_forward disabled" || err "2/6 ip_forward still enabled!"

    [ "$(sysctl -n net.ipv4.conf.all.rp_filter)" != "0" ] \
        && msg "3/6 rp_filter active (anti-spoofing)" || warn "3/6 rp_filter off"

    if [ "$USE_PORT_HOPPING" = true ]; then
        iptables -t nat -S HY-REDIR 2>/dev/null | grep -q REDIRECT \
            && msg "4/6 Port hopping active (${PORT_RANGE_START}-${PORT_RANGE_END})" \
            || err "4/6 Port hopping NOT active"
    else
        msg "4/6 Single port mode"
    fi

    iptables -S HY-OUT 2>/dev/null | grep -q REJECT \
        && msg "5/6 Egress abuse filters loaded" || err "5/6 Egress filters MISSING"

    iptables -S OUTPUT 2>/dev/null | grep -q "uid-owner ${HY_UID}" \
        && msg "6/6 Egress chain bound to hysteria user" \
        || warn "6/6 owner match unavailable — egress filters not bound"
    echo ""
}

show_info() {
    local APP_PORT
    [ "$USE_PORT_HOPPING" = true ] && APP_PORT="${PORT_RANGE_START}-${PORT_RANGE_END}" || APP_PORT="${LISTEN_PORT}"
    echo -e "${GREEN}${BOLD}=== App Settings (MinaProNet VPN) ===${NC}"
    echo -e "  UDP Server : ${BOLD}${SERVER_IP}${NC}"
    echo -e "  UDP Port   : ${BOLD}${APP_PORT}${NC}"
    echo -e "  Obfs       : ${BOLD}${OBFS}${NC}"
    echo -e "  Auth       : ${BOLD}${AUTH_STR}${NC}"
    echo -e "  UpDown     : ${BOLD}${UP_MBPS}:${DOWN_MBPS}${NC}"
    echo ""
    echo -e "${BOLD}=== Management ===${NC}"
    echo -e "  systemctl status hysteria-server"
    echo -e "  journalctl -u hysteria-guard -f      # مراقبة الفيضان الصادر"
    echo -e "  bash ${FW_SCRIPT}                    # إعادة تطبيق القواعد"
    echo -e "  bash \$0 --uninstall"
    echo ""
    umask 077
    cat > "${HYSTERIA_DIR}/connection-info.txt" << EOF
UDP Server: ${SERVER_IP}
UDP Port:   ${APP_PORT}
Obfs:       ${OBFS}
Auth:       ${AUTH_STR}
UpDown:     ${UP_MBPS}:${DOWN_MBPS}
Internal:   ${LISTEN_PORT}
EOF
    chmod 600 "${HYSTERIA_DIR}/connection-info.txt"
}

uninstall() {
    warn "Uninstalling..."
    systemctl disable --now hysteria-guard hysteria-server hysteria-firewall 2>/dev/null
    # حذف القفزات بدقة اعتمادًا على مخرجات -S (لا حذف بالأرقام = لا نلمس قواعد غيرنا)
    iptables -S 2>/dev/null | grep -E ' -j HY-(IN|OUT|ICMP)$' | sed 's/^-A/-D/' \
        | while read -r r; do iptables $r 2>/dev/null; done
    iptables -t nat -S 2>/dev/null | grep -E ' -j HY-REDIR$' | sed 's/^-A/-D/' \
        | while read -r r; do iptables -t nat $r 2>/dev/null; done
    ip6tables -S 2>/dev/null | grep -E ' -j HY-(IN|OUT|ICMP)$' | sed 's/^-A/-D/' \
        | while read -r r; do ip6tables $r 2>/dev/null; done
    ip6tables -t nat -S 2>/dev/null | grep -E ' -j HY-REDIR$' | sed 's/^-A/-D/' \
        | while read -r r; do ip6tables -t nat $r 2>/dev/null; done
    for c in HY-IN HY-OUT HY-ICMP; do
        iptables -F "$c" 2>/dev/null; iptables -X "$c" 2>/dev/null
        ip6tables -F "$c" 2>/dev/null; ip6tables -X "$c" 2>/dev/null
    done
    iptables -t nat -F HY-REDIR 2>/dev/null; iptables -t nat -X HY-REDIR 2>/dev/null
    ip6tables -t nat -F HY-REDIR 2>/dev/null; ip6tables -t nat -X HY-REDIR 2>/dev/null
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1

    rm -f "$SVC_MAIN" "$SVC_FW" "$SVC_GUARD" "$GUARD_SCRIPT" "$HYSTERIA_BIN" "$SYSCTL_FILE"
    rm -rf "$HYSTERIA_DIR"
    userdel "$HYSTERIA_USER" 2>/dev/null
    sed -i '/hysteria/d' /etc/rc.local 2>/dev/null
    systemctl daemon-reload; sysctl --system >/dev/null 2>&1
    msg "Uninstalled"
    exit 0
}

# ======================== MAIN ========================
check_root
detect_iface
[ "${1:-}" = "--uninstall" ] && uninstall

print_banner
get_server_ip
install_deps
install_hysteria
create_user
generate_cert
get_config
create_config
apply_sysctl
write_firewall_script
create_services
create_guard
systemctl daemon-reload
start_services
verify_server
show_info
echo -e "${GREEN}${BOLD}Done — server is up with abuse protections enabled.${NC}"
