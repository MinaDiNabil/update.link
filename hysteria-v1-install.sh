#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  MinaProNet – UDP Hysteria Manager
#  قائمة إدارة كاملة للتحكم في سيرفر Hysteria v1
#  التثبيت: sudo bash udp-menu.sh
#  الأمر   : udp
# ═══════════════════════════════════════════════════════════════════════════════

# ── الألوان ───────────────────────────────────────────────────────────────────
R='\033[0;31m';  G='\033[0;32m';  Y='\033[1;33m'
C='\033[0;36m';  B='\033[1m';     P='\033[0;35m'
W='\033[1;37m';  NC='\033[0m'

# ── المسارات الثابتة ─────────────────────────────────────────────────────────
HYSTERIA_BIN="/usr/local/bin/hysteria"
HYSTERIA_CONFIG="/etc/hysteria/config.json"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_LOG="/var/log/hysteria"
IPTABLES_SCRIPT="/etc/hysteria/port-hopping.sh"

# ══════════════════════════════════════════════════════════════════════════════
#  دوال مساعدة
# ══════════════════════════════════════════════════════════════════════════════
clear_screen() { clear; }

pause() {
    echo ""
    echo -e "${Y}اضغط Enter للمتابعة ...${NC}"
    read -r
}

confirm() {
    local msg="${1:-هل أنت متأكد؟}"
    echo -e "${Y}⚠️  $msg [y/N]: ${NC}"
    read -r ans
    [[ "$ans" =~ ^[yY]$ ]]
}

is_installed() { [[ -f "$HYSTERIA_BIN" && -f "$HYSTERIA_CONFIG" ]]; }

get_status() {
    if systemctl is-active --quiet hysteria 2>/dev/null; then
        echo -e "${G}● يعمل${NC}"
    else
        echo -e "${R}● متوقف${NC}"
    fi
}

get_config_val() {
    # $1 = مفتاح JSON مثل: .obfs  أو  .auth.config.password
    python3 -c "import json,sys; d=json.load(open('$HYSTERIA_CONFIG')); \
        keys='$1'.strip('.').split('.'); \
        v=d; [v := v[k] for k in keys]; print(v)" 2>/dev/null || echo "—"
}

set_config_val() {
    # $1 = مسار JSON  $2 = قيمة جديدة  $3 = type (str/int)
    local jpath="$1" val="$2" typ="${3:-str}"
    python3 << PYEOF
import json
with open("$HYSTERIA_CONFIG","r") as f:
    d = json.load(f)

keys = "$jpath".strip(".").split(".")
node = d
for k in keys[:-1]:
    node = node[k]

if "$typ" == "int":
    node[keys[-1]] = int("$val")
else:
    node[keys[-1]] = "$val"

with open("$HYSTERIA_CONFIG","w") as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
print("OK")
PYEOF
}

header() {
    clear_screen
    echo -e "${B}${C}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║        🚀  MinaProNet – UDP Hysteria Manager            ║"
    echo "  ╚══════════════════════════════════════════════════════════╝${NC}"
    if is_installed; then
        local STATUS PORT OBFS PASS UP DOWN
        STATUS=$(get_status)
        PORT=$(grep -oP '"listen":\s*":\K[^"]+' "$HYSTERIA_CONFIG" 2>/dev/null || echo "—")
        OBFS=$(get_config_val ".obfs")
        PASS=$(get_config_val ".auth.config.password")
        UP=$(get_config_val ".up_mbps")
        DOWN=$(get_config_val ".down_mbps")
        echo ""
        echo -e "  ${W}الحالة   :${NC} $STATUS"
        echo -e "  ${W}البورت   :${NC} ${C}$PORT${NC}  ${W}|  Obfs:${NC} ${C}$OBFS${NC}"
        echo -e "  ${W}الباسورد :${NC} ${P}$PASS${NC}"
        echo -e "  ${W}السرعة   :${NC} ${G}↑ ${UP} Mbps${NC}  /  ${G}↓ ${DOWN} Mbps${NC}"
    else
        echo ""
        echo -e "  ${R}⚠  Hysteria غير مثبّت${NC}"
    fi
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
#  القوائم
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. إدارة الخدمة ──────────────────────────────────────────────────────────
menu_service() {
    while true; do
        header
        echo -e "  ${B}${Y}[ إدارة الخدمة ]${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  ▶  تشغيل Hysteria"
        echo -e "  ${W}[2]${NC}  ■  إيقاف Hysteria"
        echo -e "  ${W}[3]${NC}  ↺  إعادة التشغيل"
        echo -e "  ${W}[4]${NC}  ↺  Reload (بدون انقطاع)"
        echo -e "  ${W}[5]${NC}  ✓  حالة الخدمة (مفصّلة)"
        echo -e "  ${W}[6]${NC}  📋  آخر 50 سطر من اللوق"
        echo -e "  ${W}[7]${NC}  📋  اللوق المباشر (live)"
        echo -e "  ${W}[8]${NC}  📋  لوق الأخطاء"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1) systemctl start  hysteria && echo -e "${G}تم التشغيل${NC}" || echo -e "${R}فشل${NC}"; pause ;;
            2) confirm "إيقاف Hysteria؟" && systemctl stop hysteria && echo -e "${G}تم الإيقاف${NC}"; pause ;;
            3) systemctl restart hysteria && echo -e "${G}تمت إعادة التشغيل${NC}"; pause ;;
            4) systemctl reload  hysteria && echo -e "${G}تم Reload${NC}" || systemctl restart hysteria; pause ;;
            5) systemctl status  hysteria --no-pager -l; pause ;;
            6) tail -n 50 "$HYSTERIA_LOG/hysteria.log" 2>/dev/null || journalctl -u hysteria -n 50 --no-pager; pause ;;
            7) echo -e "${Y}اضغط Ctrl+C للخروج${NC}"; tail -f "$HYSTERIA_LOG/hysteria.log" 2>/dev/null || journalctl -u hysteria -f ;;
            8) tail -n 50 "$HYSTERIA_LOG/hysteria-error.log" 2>/dev/null; pause ;;
            0) return ;;
        esac
    done
}

# ── 2. تعديل الإعدادات ───────────────────────────────────────────────────────
menu_settings() {
    while true; do
        header
        echo -e "  ${B}${Y}[ تعديل الإعدادات ]${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  🔌  تغيير البورت"
        echo -e "  ${W}[2]${NC}  🔑  تغيير كلمة السر (Auth)"
        echo -e "  ${W}[3]${NC}  🌀  تغيير Obfuscation"
        echo -e "  ${W}[4]${NC}  ⚡  تغيير سرعة الرفع (up_mbps)"
        echo -e "  ${W}[5]${NC}  ⚡  تغيير سرعة التنزيل (down_mbps)"
        echo -e "  ${W}[6]${NC}  ⚡  تغيير سرعة الرفع والتنزيل معاً"
        echo -e "  ${W}[7]${NC}  🪟  تغيير recv_window_conn"
        echo -e "  ${W}[8]${NC}  🪟  تغيير recv_window_client"
        echo -e "  ${W}[9]${NC}  📄  عرض config.json الحالي"
        echo -e "  ${W}[10]${NC} ✏️   تعديل config.json يدوياً (nano)"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1)
                echo -ne "  ${C}البورت الجديد (حالي: $(get_config_val '.listen' | tr -d ':')): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                python3 -c "
import json
with open('$HYSTERIA_CONFIG','r') as f: d=json.load(f)
d['listen']=':$val'
with open('$HYSTERIA_CONFIG','w') as f: json.dump(d,f,indent=2)
print('OK')"
                # تحديث Port Hopping
                if [[ -f "$IPTABLES_SCRIPT" ]]; then
                    sed -i "s/MAIN_PORT=\"[0-9]*\"/MAIN_PORT=\"$val\"/" "$IPTABLES_SCRIPT"
                    bash "$IPTABLES_SCRIPT" apply
                fi
                echo -e "${G}تم تغيير البورت إلى $val${NC}"
                confirm "إعادة تشغيل Hysteria الآن؟" && systemctl restart hysteria
                pause ;;
            2)
                echo -ne "  ${C}كلمة السر الجديدة: ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".auth.config.password" "$val"
                echo -e "${G}تم تغيير كلمة السر${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            3)
                echo -ne "  ${C}Obfs الجديد (حالي: $(get_config_val '.obfs')): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".obfs" "$val"
                echo -e "${G}تم تغيير Obfs${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            4)
                echo -ne "  ${C}سرعة الرفع Mbps (0=غير محدود): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".up_mbps" "$val" "int"
                echo -e "${G}تم تغيير up_mbps إلى $val${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            5)
                echo -ne "  ${C}سرعة التنزيل Mbps (0=غير محدود): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".down_mbps" "$val" "int"
                echo -e "${G}تم تغيير down_mbps إلى $val${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            6)
                echo -ne "  ${C}سرعة الرفع Mbps: ${NC}"; read -r up
                echo -ne "  ${C}سرعة التنزيل Mbps: ${NC}"; read -r dn
                [[ -z "$up" || -z "$dn" ]] && continue
                set_config_val ".up_mbps"   "$up" "int"
                set_config_val ".down_mbps" "$dn" "int"
                echo -e "${G}تم: ↑$up / ↓$dn Mbps${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            7)
                echo -ne "  ${C}recv_window_conn (حالي: $(get_config_val '.recv_window_conn')): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".recv_window_conn" "$val" "int"
                echo -e "${G}تم${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            8)
                echo -ne "  ${C}recv_window_client (حالي: $(get_config_val '.recv_window_client')): ${NC}"
                read -r val
                [[ -z "$val" ]] && continue
                set_config_val ".recv_window_client" "$val" "int"
                echo -e "${G}تم${NC}"
                confirm "إعادة تشغيل؟" && systemctl restart hysteria
                pause ;;
            9)
                echo ""
                cat "$HYSTERIA_CONFIG"
                pause ;;
            10)
                nano "$HYSTERIA_CONFIG"
                confirm "إعادة تشغيل بعد التعديل؟" && systemctl restart hysteria ;;
            0) return ;;
        esac
    done
}

# ── 3. Port Hopping ──────────────────────────────────────────────────────────
menu_porthopping() {
    while true; do
        header
        echo -e "  ${B}${Y}[ Port Hopping ]${NC}"
        echo ""
        # اقرأ القيم الحالية من السكربت
        local CUR_START CUR_END CUR_IFACE
        CUR_START=$(grep 'HOP_START=' "$IPTABLES_SCRIPT" 2>/dev/null | head -1 | grep -oP '"[^"]+"' | tr -d '"' || echo "1")
        CUR_END=$(grep 'HOP_END='   "$IPTABLES_SCRIPT" 2>/dev/null | head -1 | grep -oP '"[^"]+"' | tr -d '"' || echo "65535")
        CUR_IFACE=$(grep 'IFACE='   "$IPTABLES_SCRIPT" 2>/dev/null | head -1 | grep -oP '"[^"]+"' | tr -d '"' || echo "eth0")
        echo -e "  ${W}النطاق الحالي :${NC} ${C}UDP ${CUR_START}–${CUR_END}${NC}"
        echo -e "  ${W}الواجهة       :${NC} ${C}$CUR_IFACE${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  ✅  تفعيل Port Hopping (تطبيق القواعد)"
        echo -e "  ${W}[2]${NC}  ❌  إيقاف Port Hopping"
        echo -e "  ${W}[3]${NC}  🔢  تغيير نطاق البورتات"
        echo -e "  ${W}[4]${NC}  🌐  تغيير الواجهة الشبكية"
        echo -e "  ${W}[5]${NC}  👁️   عرض قواعد iptables PREROUTING"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1)
                bash "$IPTABLES_SCRIPT" apply
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                netfilter-persistent save 2>/dev/null || true
                echo -e "${G}Port Hopping مفعّل${NC}"; pause ;;
            2)
                confirm "إيقاف Port Hopping؟" && bash "$IPTABLES_SCRIPT" remove
                echo -e "${Y}تم الإيقاف – يمكن إعادة التفعيل من الخيار 1${NC}"; pause ;;
            3)
                echo -ne "  ${C}بداية النطاق (${CUR_START}): ${NC}"; read -r s
                echo -ne "  ${C}نهاية النطاق  (${CUR_END}): ${NC}"; read -r e
                [[ -z "$s" ]] && s="$CUR_START"
                [[ -z "$e" ]] && e="$CUR_END"
                sed -i "s/HOP_START=\"[^\"]*\"/HOP_START=\"$s\"/" "$IPTABLES_SCRIPT"
                sed -i "s/HOP_END=\"[^\"]*\"/HOP_END=\"$e\""     "$IPTABLES_SCRIPT"
                bash "$IPTABLES_SCRIPT" apply
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                echo -e "${G}تم: UDP $s–$e${NC}"; pause ;;
            4)
                echo -ne "  ${C}الواجهة (eth0/ens3/...): ${NC}"; read -r iface
                [[ -z "$iface" ]] && continue
                sed -i "s/IFACE=\"[^\"]*\"/IFACE=\"$iface\"/" "$IPTABLES_SCRIPT"
                bash "$IPTABLES_SCRIPT" apply
                echo -e "${G}تم تغيير الواجهة إلى $iface${NC}"; pause ;;
            5)
                echo ""
                iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null
                pause ;;
            0) return ;;
        esac
    done
}

# ── 4. المراقبة والإحصائيات ─────────────────────────────────────────────────
menu_monitor() {
    while true; do
        header
        echo -e "  ${B}${Y}[ المراقبة والإحصائيات ]${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  📊  عرض الاتصالات النشطة"
        echo -e "  ${W}[2]${NC}  🌐  فحص البورت ${C}$(get_config_val '.listen' | tr -d ':')${NC}"
        echo -e "  ${W}[3]${NC}  💾  استخدام الذاكرة و CPU"
        echo -e "  ${W}[4]${NC}  📋  Health-check الأخير"
        echo -e "  ${W}[5]${NC}  🔄  مراقبة الـ cron"
        echo -e "  ${W}[6]${NC}  🗑️   حذف ملفات اللوق القديمة"
        echo -e "  ${W}[7]${NC}  📶  اختبار سرعة السيرفر"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1)
                echo ""
                echo -e "${C}── الاتصالات UDP النشطة ───────────────────${NC}"
                ss -unp 2>/dev/null | grep hysteria || echo "لا يوجد اتصالات حالياً"
                echo ""
                echo -e "${C}── إجمالي الاتصالات ───────────────────────${NC}"
                ss -unp 2>/dev/null | grep -c hysteria || echo "0"
                pause ;;
            2)
                local PORT
                PORT=$(get_config_val '.listen' | tr -d ':')
                echo ""
                echo -e "${C}── فحص البورت $PORT ──────────────────────────${NC}"
                if ss -ulnp 2>/dev/null | grep -q ":$PORT"; then
                    echo -e "${G}✅ البورت $PORT يستمع${NC}"
                else
                    echo -e "${R}❌ البورت $PORT لا يستمع!${NC}"
                fi
                echo ""
                ss -ulnp 2>/dev/null | grep ":$PORT" || true
                pause ;;
            3)
                echo ""
                echo -e "${C}── CPU & Memory ──────────────────────────${NC}"
                PID=$(pgrep -f "hysteria server" | head -1 || echo "")
                if [[ -n "$PID" ]]; then
                    ps -p "$PID" -o pid,pcpu,pmem,rss,vsz,etime --no-headers 2>/dev/null | \
                    awk '{printf "PID: %s | CPU: %s%% | MEM: %s%% | RSS: %s KB | Time: %s\n",$1,$2,$3,$4,$6}'
                else
                    echo -e "${R}Hysteria غير شغّال${NC}"
                fi
                echo ""
                echo -e "${C}── إجمالي الذاكرة ────────────────────────${NC}"
                free -h
                pause ;;
            4)
                echo ""
                tail -n 30 "$HYSTERIA_LOG/healthcheck.log" 2>/dev/null || echo "لا يوجد لوق health-check"
                pause ;;
            5)
                echo ""
                crontab -l 2>/dev/null | grep hysteria || echo "لا يوجد cron"
                pause ;;
            6)
                confirm "حذف ملفات اللوق القديمة؟" || continue
                find "$HYSTERIA_LOG" -name "*.log" -mtime +7 -delete 2>/dev/null
                echo -e "${G}تم الحذف${NC}"; pause ;;
            7)
                echo ""
                echo -e "${C}── اختبار السرعة عبر speedtest-cli ────────${NC}"
                if command -v speedtest-cli &>/dev/null; then
                    speedtest-cli --simple
                elif command -v speedtest &>/dev/null; then
                    speedtest
                else
                    apt-get install -y -qq speedtest-cli 2>/dev/null && speedtest-cli --simple
                fi
                pause ;;
            0) return ;;
        esac
    done
}

# ── 5. النسخ الاحتياطي والاستعادة ───────────────────────────────────────────
menu_backup() {
    while true; do
        header
        echo -e "  ${B}${Y}[ النسخ الاحتياطي ]${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  💾  إنشاء نسخة احتياطية"
        echo -e "  ${W}[2]${NC}  📂  عرض النسخ المتاحة"
        echo -e "  ${W}[3]${NC}  ♻️   استعادة نسخة احتياطية"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1)
                local BFILE="/root/hysteria-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
                tar -czf "$BFILE" "$HYSTERIA_DIR" 2>/dev/null
                echo -e "${G}✅ نسخة احتياطية: $BFILE${NC}"
                ls -lh "$BFILE"
                pause ;;
            2)
                echo ""
                ls -lht /root/hysteria-backup-*.tar.gz 2>/dev/null || echo "لا توجد نسخ"
                pause ;;
            3)
                echo ""
                ls -1 /root/hysteria-backup-*.tar.gz 2>/dev/null || { echo "لا توجد نسخ"; pause; continue; }
                echo -ne "\n  ${C}أدخل اسم الملف: ${NC}"
                read -r bfile
                [[ ! -f "$bfile" ]] && echo -e "${R}الملف غير موجود${NC}" && pause && continue
                confirm "استعادة من $bfile؟" || continue
                systemctl stop hysteria 2>/dev/null || true
                tar -xzf "$bfile" -C / 2>/dev/null
                systemctl restart hysteria
                echo -e "${G}تم الاستعادة وإعادة التشغيل${NC}"
                pause ;;
            0) return ;;
        esac
    done
}

# ── 6. التثبيت / الإلغاء ────────────────────────────────────────────────────
menu_install() {
    while true; do
        header
        echo -e "  ${B}${Y}[ التثبيت والصيانة ]${NC}"
        echo ""
        echo -e "  ${W}[1]${NC}  🔄  تحديث Hysteria إلى آخر إصدار"
        echo -e "  ${W}[2]${NC}  🔐  تجديد شهادة TLS"
        echo -e "  ${W}[3]${NC}  🔀  إعادة تطبيق إعدادات Port Hopping"
        echo -e "  ${W}[4]${NC}  🛠️   إصلاح الخدمة (repair)"
        echo -e "  ${W}[5]${NC}  ${R}🗑️   إلغاء تثبيت Hysteria كاملاً${NC}"
        echo -e "  ${W}[0]${NC}  ←  رجوع"
        echo ""
        read -rp "  اختر: " ch
        case "$ch" in
            1)
                local ARCH HY_ARCH URL TMP VER="v1.3.5"
                ARCH=$(uname -m)
                HY_ARCH="amd64"; [[ "$ARCH" == "aarch64" ]] && HY_ARCH="arm64"
                URL="https://github.com/apernet/hysteria/releases/download/${VER}/hysteria-linux-${HY_ARCH}"
                TMP=$(mktemp)
                info "جاري التحميل …"
                if curl -L --retry 3 --progress-bar -o "$TMP" "$URL" 2>/dev/null; then
                    local SZ
                    SZ=$(stat -c%s "$TMP")
                    if [[ "$SZ" -gt 1048576 ]] && file "$TMP" | grep -q ELF; then
                        chmod +x "$TMP"
                        systemctl stop hysteria 2>/dev/null || true
                        mv "$TMP" "$HYSTERIA_BIN"
                        systemctl start hysteria
                        echo -e "${G}✅ تم التحديث إلى $VER${NC}"
                    else
                        echo -e "${R}الملف تالف${NC}"; rm -f "$TMP"
                    fi
                else
                    echo -e "${R}فشل التحميل${NC}"; rm -f "$TMP"
                fi
                pause ;;
            2)
                local DOMAIN
                DOMAIN=$(openssl x509 -in "$HYSTERIA_DIR/server.crt" -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+' || echo "unknown")
                confirm "تجديد شهادة TLS للدومين $DOMAIN؟" || continue
                systemctl stop hysteria 2>/dev/null || true
                openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
                    -keyout "$HYSTERIA_DIR/server.key" \
                    -out    "$HYSTERIA_DIR/server.crt" \
                    -subj   "/C=EG/O=MinaProNet/CN=${DOMAIN}" \
                    -addext "subjectAltName=DNS:${DOMAIN}" 2>/dev/null
                chmod 600 "$HYSTERIA_DIR/server.key" "$HYSTERIA_DIR/server.crt"
                systemctl start hysteria
                echo -e "${G}✅ تم تجديد الشهادة (10 سنوات)${NC}"
                pause ;;
            3)
                [[ -f "$IPTABLES_SCRIPT" ]] && bash "$IPTABLES_SCRIPT" apply \
                    && echo -e "${G}تم تطبيق Port Hopping${NC}" \
                    || echo -e "${R}سكربت Port Hopping غير موجود${NC}"
                pause ;;
            4)
                info "إصلاح الخدمة …"
                systemctl daemon-reload
                systemctl enable hysteria 2>/dev/null || true
                [[ -f "$IPTABLES_SCRIPT" ]] && bash "$IPTABLES_SCRIPT" apply || true
                systemctl restart hysteria
                sleep 2
                get_status
                pause ;;
            5)
                confirm "⚠️  حذف Hysteria كاملاً من السيرفر؟" || continue
                confirm "⚠️  تأكيد أخير – هذا لا يمكن التراجع عنه!" || continue
                systemctl stop hysteria 2>/dev/null || true
                systemctl disable hysteria 2>/dev/null || true
                rm -f /etc/systemd/system/hysteria.service
                rm -f "$HYSTERIA_BIN"
                rm -rf "$HYSTERIA_DIR"
                rm -rf "$HYSTERIA_LOG"
                rm -f /etc/logrotate.d/hysteria
                rm -f /usr/local/bin/hysteria-check.sh
                crontab -l 2>/dev/null | grep -v "hysteria-check" | crontab - 2>/dev/null || true
                systemctl daemon-reload
                echo -e "${G}✅ تم إلغاء التثبيت بالكامل${NC}"
                pause; return ;;
            0) return ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  القائمة الرئيسية
# ══════════════════════════════════════════════════════════════════════════════
main_menu() {
    while true; do
        header
        echo -e "  ${B}${W}القائمة الرئيسية${NC}"
        echo ""
        echo -e "  ${C}[1]${NC}  ⚙️   إدارة الخدمة        (تشغيل / إيقاف / اللوق)"
        echo -e "  ${C}[2]${NC}  🔧  الإعدادات            (باسورد / بورت / سرعة)"
        echo -e "  ${C}[3]${NC}  🔀  Port Hopping         (1–65535)"
        echo -e "  ${C}[4]${NC}  📊  المراقبة             (اتصالات / CPU / لوق)"
        echo -e "  ${C}[5]${NC}  💾  النسخ الاحتياطي"
        echo -e "  ${C}[6]${NC}  🛠️   التثبيت والصيانة     (تحديث / إصلاح / حذف)"
        echo ""
        echo -e "  ${R}[0]${NC}  🚪  خروج"
        echo ""
        read -rp "  اختر: " choice
        case "$choice" in
            1) menu_service     ;;
            2) menu_settings    ;;
            3) menu_porthopping ;;
            4) menu_monitor     ;;
            5) menu_backup      ;;
            6) menu_install     ;;
            0) clear_screen; exit 0 ;;
            *) echo -e "${R}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════
[[ $EUID -ne 0 ]] && echo -e "${R}يجب تشغيل السكربت كـ root: sudo bash udp-menu.sh${NC}" && exit 1
! is_installed && echo -e "${Y}تنبيه: Hysteria غير مثبّت – بعض الخيارات لن تعمل${NC}" && sleep 2
main_menu
