#!/usr/bin/env bash
# ============================================================
#  MinaProNet VPN - Unlimited Multi-User Hysteria Fix
# ============================================================

set -uo pipefail

# 1. تهيئة ملفات النواة لتتحمل ملايين اتصالات UDP بدون انقطاع
cat > /etc/sysctl.d/99-hysteria-multiuser.conf << 'EOF'
# رفع الحد الأقصى لاتصالات التتبع إلى 2 مليون اتصال
net.netfilter.nf_conntrack_max = 2097152

# تقليل زمن تنظيف اتصالات UDP الميتة لعدم خنق السيرفر
net.netfilter.nf_conntrack_udp_timeout = 5
net.netfilter.nf_conntrack_udp_timeout_stream = 20

# رفع الذاكرة المؤقتة لمقابس الشبكة (UDP Buffers)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 100000
net.core.somaxconn = 65535

# تفعيل التوجيه
net.ipv4.ip_forward = 1
EOF

sysctl -p /etc/sysctl.d/99-hysteria-multiuser.conf >/dev/null 2>&1 || true

# 2. إعادة ضبط إعدادات Hysteria لاستيعاب 8192 عميل متزامن
cat > /etc/hysteria/config.json << 'EOF'
{
    "listen": ":36712",
    "cert": "/etc/hysteria/server.crt",
    "key": "/etc/hysteria/server.key",
    "obfs": "minapronet",
    "auth": {
        "mode": "password",
        "config": {
            "password": "2a1d4b9896e:7823f72fcd10:16fbcee5gf"
        }
    },
    "up_mbps": 500,
    "down_mbps": 1000,
    "disable_udp": false,
    "recv_window_conn": 33554432,
    "recv_window_client": 134217728,
    "max_conn_client": 8192,
    "disable_mtu_discovery": true
}
EOF

# 3. تحديث خدمات Systemd لفتح الملفات بدون حد أقصى (Unlimited Descriptors)
cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria UDP Server Unlimited Multi-User
After=network-online.target hysteria-firewall.service
Wants=network-online.target

[Service]
Type=simple
User=hysteria
Group=hysteria
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
LimitNPROC=1048576
LimitMEMLOCK=infinity
TasksMax=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# 4. إعادة بناء قواعد iptables بنظام التوجيه السريع
cat > /etc/hysteria/firewall.sh << 'EOFW'
#!/usr/bin/env bash
LISTEN_PORT="36712"

iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true

# توجيه منافذ UDP مباشرة
iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports $LISTEN_PORT
iptables -A INPUT -p udp -j ACCEPT

exit 0
EOFW

chmod 750 /etc/hysteria/firewall.sh
bash /etc/hysteria/firewall.sh

# 5. تطبيق التغييرات وإعادة التشغيل
systemctl daemon-reload
systemctl restart hysteria-server

echo "تم تطبيق إصلاحات المستخدمين المتعددين بنجاح."
