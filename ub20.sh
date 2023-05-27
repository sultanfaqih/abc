clear
echo -e "\033[33m# //====================================================\e[0m"
echo -e "\033[33m# //	System Request:Debian 9-10/Ubuntu 18.04+/20.04\e[0m"
echo -e "\033[33m# //	Author:	bhoikfostyahya\e[0m"
echo -e "\033[33m# //	Description: Xray Menu Management\e[0m"
echo -e "\033[33m# //	email: admin@bhoikfostyahya.com\e[0m"
echo -e "\033[33m# //   telegram: t.me/bhoikfost_yahya\e[0m"
echo -e "\033[33m# //====================================================\e[0m"
sleep 1
# // FONT color configuration | BHOIKFOST YAHYA AUTOSCRIPT
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

# // configuration GET | BHOIKFOST YAHYA AUTOSCRIPT
TIMES="10"
NAMES=$(whoami)
IMP="wget -q -O"
CHATID="-1001707197017"
LOCAL_DATE="/usr/bin/"
MYIP=$(wget -qO- ipinfo.io/ip)
CITY=$(wget -qO- ipinfo.io/city)
TIME=$(date '+%d %b %Y')
RAMMS=$(free -m | awk 'NR==2 {print $2}')
KEY="5991497887:AAFXAUCGrhogt_ueavcgtq6GXN_Ftwu_KdM"
URL="https://api.telegram.org/bot$KEY/sendMessage"
GITHUB_CMD="https://github.com/FighterTunnel/tunnel/raw/"
NAMECOM=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $2}')
OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
Date_list=$(date +"%Y-%m-%d" -d "$dateFromServer")
source '/etc/os-release'
cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

INS="sudo apt-get install -y"
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

judge() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 Complete... | thx to ${YELLOW}bhoikfostyahya${FONT}"
        sleep 1
    fi
}

function nginx_install() {
    apt clean all && apt update
    ntpdate pool.ntp.org
    apt -y install chrony
    apt install curl pwgen chrony socat openssl netcat cron -y

    source <(curl -sL ${GITHUB_CMD}main/fodder/FighterTunnel-examples/Documentation/bbr)
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        judge "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        rm -f /etc/apt/sources.list.d/nginx.list
        $INS curl gnupg2 ca-certificates lsb-release ubuntu-keyring
        curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
            tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" |
            tee /etc/apt/sources.list.d/nginx.list
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" |
            tee /etc/apt/preferences.d/99nginx

        apt update -y
        ${INS} nginx
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        judge "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        INS="apt install -y"
        rm -f /etc/apt/sources.list.d/nginx.list
        $INS curl gnupg2 ca-certificates lsb-release debian-archive-keyring
        curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor |
            tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian $(lsb_release -cs) nginx" |
            tee /etc/apt/sources.list.d/nginx.list
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" |
            tee /etc/apt/preferences.d/99nginx

        apt update -y
        ${INS} nginx
    else
        echo -e "${RED} Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC} )"
        exit 1
    fi
    apt-get purge apache2 -y
    apt-get autoremove -y
}
function LOGO() {
    echo -e "
    ┌───────────────────────────────────────────────┐
 ───│                                               │───
 ───│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───
 ───│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───
 ───│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───
    │    ${YELLOW}Copyright${FONT} (C)${GRAY}https://t.me/kytxz$NC   │
    └───────────────────────────────────────────────┘
         ${RED}Autoscript xray vpn lite (multi port)${FONT}    
${RED}Make sure the internet is smooth when installing the script${FONT}
        "

}
function install_xray() {
    judge "Core Xray 1.7.5 Version installed successfully"
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.7.5
    curl https://rclone.org/install.sh | bash
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${GITHUB_CMD}main/RCLONE%2BBACKUP-Gdrive/rclone.conf" >/dev/null 2>&1
    wget -O /etc/xray/config.json "${GITHUB_CMD}main/VMess-VLESS-Trojan%2BWebsocket%2BgRPC/config.json" >/dev/null 2>&1
    wget -O /usr/bin/ws "${GITHUB_CMD}main/fodder/websocket/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${GITHUB_CMD}main/fodder/websocket/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${GITHUB_CMD}main/fodder/websocket/ws.service" >/dev/null 2>&1
    wget -q -O /etc/ipserver "${GITHUB_CMD}main/fodder/FighterTunnel-examples/ipserver" && bash /etc/ipserver >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user ftvpn99@gmail.com
from ftvpn99@gmail.com
password tqxchjahewgxmkue
logfile ~/.msmtp.log

EOF

    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=FighterTunnel Server Xray
Documentation=https://t.me/fightertunnell
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

}

function download_config() {
    cd
    rm -rf *
    curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
    wget -O /etc/haproxy/haproxy.cfg "${GITHUB_CMD}main/fodder/FighterTunnel-examples/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${GITHUB_CMD}main/fodder/nginx/xray" >/dev/null 2>&1
    wget -O /usr/bin/udp "${GITHUB_CMD}main/fodder/bhoikfostyahya/udp-custom-linux-amd64" >/dev/null 2>&1
    wget -O /etc/nginx/nginx.conf "${GITHUB_CMD}main/fodder/nginx/nginx.conf" >/dev/null 2>&1
    wget https://github.com/FighterTunnel/tunnel/raw/main/fodder/bhoikfostyahya/XrayFT.zip >/dev/null 2>&1
    7z e -pKarawang123@nuryahya XrayFT.zip
    unzip ftvpn.zip
    mv ftvpn /etc
    rm -f XrayFT.zip
    rm -f ftvpn.zip
    chmod +x *
    chmod +x /usr/bin/udp
    mv * /usr/bin/

    cat >/root/.profile <<END
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
END
    cat >/usr/bin/config.json <<-END
{
  "listen": ":65535",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
END
    cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/bin/xp
	END
    cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/59 * * * * root /usr/bin/logclean
	END
    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END

    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END
    cat >/etc/cron.d/x_limp <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/10 * * * * root /usr/bin/xraylimit
	END
    cat >/etc/systemd/system/rc-local.service <<-END
		[Unit]
		Description=/etc/rc.local
		ConditionPathExists=/etc/rc.local
		[Service]
		Type=forking
		ExecStart=/etc/rc.local start
		TimeoutSec=0
		StandardOutput=tty
		RemainAfterExit=yes
		SysVStartPriority=99
		[Install]
		WantedBy=multi-user.target
	END

    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells
    cat >/etc/rc.local <<-END
		#!/bin/sh -e
		# rc.local
		# By default this script does nothing.
		iptables -I INPUT -p udp --dport 5300 -j ACCEPT
		iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
		systemctl restart netfilter-persistent
		exit 0
	END
    chmod +x /etc/rc.local

    apt install squid -y
    wget -q -O /etc/squid/squid.conf "${GITHUB_CMD}main/fodder/FighterTunnel-examples/squid.conf" >/dev/null 2>&1
    wget -q -O /etc/default/dropbear "${GITHUB_CMD}main/fodder/FighterTunnel-examples/dropbear" >/dev/null 2>&1
    wget -q -O /etc/ssh/sshd_config "${GITHUB_CMD}main/fodder/FighterTunnel-examples/sshd" >/dev/null 2>&1
    wget -q -O /etc/fightertunnel.txt "${GITHUB_CMD}main/fodder/FighterTunnel-examples/banner" >/dev/null 2>&1
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
}

function acme() {
    #    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    judge "installed successfully SSL certificate generation script"
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop haproxy
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/yha.pem
    chown www-data.www-data /etc/xray/xray.key
    chown www-data.www-data /etc/xray/xray.crt
    judge "Installed slowdns"
    wget -q -O /etc/nameserver "${GITHUB_CMD}main/X-SlowDNS/nameserver" && bash /etc/nameserver >/dev/null 2>&1

}
instalbot() {
    cd
    UUID=$(tr </dev/urandom -dc a-z | head -c8)
    PB=$(cat /etc/slowdns/server.pub)
    NS=$(cat /etc/xray/dns)
    SD=$(cat /etc/xray/domain)
    pip3.8 install --upgrade pip
    pip3.8 install -r /etc/ftvpn/requirements.txt
    pip3.8 install pyarmor

    cd
    cat >/etc/ftvpn/var.txt <<EOF
BOT_TOKEN="$TOKET"
ADMIN="$IDTELE"
DOMAIN="${SD}"
PUB="${PB}"
HOST="${NS}"
SESSIONS="${UUID}"
EOF

    cat >/usr/bin/runbot <<EOF
#!/bin/bash

cd /etc
python3.8 -m ftvpn
EOF
    cat >/etc/systemd/system/botftvpn.service <<EOF
[Unit]
Description=FTVPN BOT 
Documentation=FighterTunnel
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/runbot

[Install]
WantedBy=multi-user.target

EOF

    cat >/etc/systemd/system/udp.service <<EOF
[Unit]
Description=FTVPN UDP HC 

[Service]
User=root
Type=simple
ExecStart=/usr/bin/udp server
WorkingDirectory=/usr/bin/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
    chmod +x /usr/bin/runbot
    systemctl daemon-reload
    systemctl stop botftvpn
    systemctl enable botftvpn
    systemctl start botftvpn
    systemctl restart botftvpn
    systemctl enable udp
    systemctl start udp
    systemctl restart udp
}
function configure_nginx() {
    # // nginx config | BHOIKFOST YAHYA AUTOSCRIPT
    cd
    rm /var/www/html/*.html
    rm /etc/nginx/conf.d/default.conf
    wget ${GITHUB_CMD}main/fodder/web.zip >/dev/null 2>&1
    unzip -x web.zip
    rm -f web.zip
    mv * /var/www/html/
    judge "Nginx configuration modification"
}

function restart_system() {
    USRSC=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $2}')
    EXPSC=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $3}')
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
<code>────────────────────</code>
<b>⚠️AUTOSCRIPT PREMIUM⚠️</b>
<code>────────────────────</code>
<code>Owner  : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$MYIP</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from</i>
<i>Github FighterTunnel</i> 
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ🐳","url":"https://t.me/yha_bot"},{"text":"ɪɴꜱᴛᴀʟʟ🐬","url":"https://t.me/channel_fightertunnell/25"}]]}'
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    cp /etc/openvpn/*.ovpn /var/www/html/
    sed -i "s/xxx/${domain}/g" /var/www/html/index.html
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${MYIP}/g" /etc/squid/squid.conf
    chown -R www-data:www-data /etc/msmtprc
    source <(curl -sL ${GITHUB_CMD}main/fodder/FighterTunnel-examples/Documentation/tunlp)
    systemctl daemon-reload
    systemctl enable client
    systemctl enable server
    systemctl enable netfilter-persistent
    systemctl enable ws
    systemctl enable haproxy
    print_ok "Processing restart service ..."
    systemctl start client
    systemctl start server
    systemctl start haproxy
    systemctl start netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart sshd
    systemctl restart rc-local
    systemctl restart client
    systemctl restart server
    systemctl restart dropbear
    systemctl restart ws
    systemctl restart openvpn
    systemctl restart cron
    systemctl restart haproxy
    systemctl restart netfilter-persistent
    systemctl restart ws
    clear
    LOGO
    echo "    ┌─────────────────────────────────────────────────────┐"
    echo "    │       >>> Service & Port                            │"
    echo "    │   - Open SSH                : 22                    │"
    echo "    │   - UDP SSH                 : 1-65535               │"
    echo "    │   - DNS (SLOWDNS)           : 443, 80, 53           │"
    echo "    │   - Dropbear                : 443, 109, 143         │"
    echo "    │   - Dropbear Websocket      : 443, 109              │"
    echo "    │   - SSH Websocket SSL       : 443                   │"
    echo "    │   - SSH Websocket           : 80                    │"
    echo "    │   - OpenVPN SSL             : 443                   │"
    echo "    │   - OpenVPN Websocket SSL   : 443                   │"
    echo "    │   - OpenVPN TCP             : 443, 1194             │"
    echo "    │   - OpenVPN UDP             : 2200                  │"
    echo "    │   - Nginx Webserver         : 443, 80, 81           │"
    echo "    │   - Haproxy Loadbalancer    : 443, 80               │"
    echo "    │   - DNS Server              : 443, 53               │"
    echo "    │   - DNS Client              : 443, 88               │"
    echo "    │   - XRAY (DNSTT/SLOWDNS)    : 443, 53               │"
    echo "    │   - XRAY Vmess TLS          : 443                   │"
    echo "    │   - XRAY Vmess gRPC         : 443                   │"
    echo "    │   - XRAY Vmess None TLS     : 80                    │"
    echo "    │   - XRAY Vless TLS          : 443                   │"
    echo "    │   - XRAY Vless gRPC         : 443                   │"
    echo "    │   - XRAY Vless None TLS     : 80                    │"
    echo "    │   - Trojan gRPC             : 443                   │"
    echo "    │   - Trojan WS               : 443                   │"
    echo "    │   - Shadowsocks WS          : 443                   │"
    echo "    │   - Shadowsocks gRPC        : 443                   │"
    echo "    │                                                     │"
    echo "    │      >>> Server Information & Other Features        │"
    echo "    │   - Timezone                : Asia/Jakarta (GMT +7) │"
    echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7        │"
    echo "    │   - Auto Delete Expired Account                     │"
    echo "    │   - Fully automatic script                          │"
    echo "    │   - VPS settings                                    │"
    echo "    │   - Admin Control                                   │"
    echo "    │   - Restore Data                                    │"
    echo "    │   - Simple BOT Telegram                             │"
    echo "    │   - Full Orders For Various Services                │"
    echo "    └─────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
    read -e -p "         Please Reboot Your Vps [y/n] " -i "y" str
    if [ "$str" = "y" ]; then

        reboot

    fi
    menu
}
function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/xray/city
    rm -rf /etc/xray/isp
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
}

function dependency_install() {
    echo ""
    echo "Please wait to install Package..."
    apt-get update
    judge "Update configuration"

    judge "Installed openvpn easy-rsa"
    source <(curl -sL ${GITHUB_CMD}main/fodder/openvpn/openvpn)
    source <(curl -sL ${GITHUB_CMD}main/BadVPN-UDPWG/ins-badvpn)

    judge "Installed itil vpn"
    wget -O /etc/pam.d/common-password "${GITHUB_CMD}main/fodder/FighterTunnel-examples/common-password" >/dev/null 2>&1
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
    judge "Installed dropbear"
    apt-get install dropbear -y

}
function install_sc() {
    dependency_install
    acme
    nginx_install
    configure_nginx
    download_config
    install_xray
    instalbot
    restart_system

}
updatepythondebian() {
    print_ok "update repository python"
    apt install python3 python3-pip -y
    sudo apt-get install build-essential checkinstall -y
    sudo apt-get install -y libreadline-gplv2-dev libncursesw5-dev libssl-dev \
        libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
    cd /opt
    sudo wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz
    sudo tar xzf Python-3.8.12.tgz
    cd Python-3.8.12
    sudo ./configure --enable-optimizations
    sudo make altinstall
}

function add_domain() {
    read -p "Input Domain :  " domain
    if [[ ${domain} ]]; then
        echo $domain >/etc/xray/domain
    else
        echo -e " ${RED}Please input your Domain${FONT}"
        echo -e ""
        echo -e " Start again in 5 seconds"
        echo -e ""
        sleep 5

        rm -rf ub20.sh
        exit 1
    fi
}
# // Prevent the default bin directory of some system xray from missing itil Hapro sshd
clear
apete_apdet() {
    apt update -y
    apt install sudo -y
    sudo apt-get clean all
    sudo apt-get autoremove -y
    ${INS} debconf-utils
    sudo apt-get remove --purge exim4 -y
    sudo apt-get remove --purge ufw firewalld -y
    ${INS} --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    ${INS} speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
    /etc/init.d/vnstat restart
    wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
    cd
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    rm -f /root/vnstat-2.6.tar.gz >/dev/null 2>&1
    rm -rf /root/vnstat-2.6 >/dev/null 2>&1
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        judge "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.\*
        updatepythondebian
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        judge "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        curl https://haproxy.debian.net/bernat.debian.org.gpg |
            gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
            http://haproxy.debian.net buster-backports-1.8 main \
            >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=1.8.\*
        updatepythondebian
    else
        echo -e "${RED} Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC} )"
        exit 1
    fi
    wget -O /usr/sbin/ftvpn "https://github.com/FighterTunnel/tunnel/raw/main/fodder/FighterTunnel-examples/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn
}
Trial_mode() {
    ipvps=$(wget -qO- ipinfo.io/ip)
    rm -rf *
    sudo git clone https://github.com/FighterTunnel/packages.git /root/masuk/ &>/dev/null
    exp=$(date -d "1 days" +"%Y-%m-%d")
    randm=$(tr </dev/urandom -dc a-z0-9 | head -c8)
    user="Trial_${randm}"
    sed -i '/#vps$/a\### '"$user $exp $ipvps"'' /root/masuk/ip
    cd /root/masuk
    sudo git config --global user.email "rullpqh02@gmail.com" &>/dev/null
    sudo git config --global user.name "FighterTunnel" &>/dev/null
    sudo rm -rf .git &>/dev/null
    sudo git init &>/dev/null
    sudo git add . &>/dev/null
    sudo git commit -m FighterTunnel &>/dev/null
    sudo git branch -M main &>/dev/null
    sudo git remote add origin https://github.com/FighterTunnel/packages.git
    sudo git push -f https://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@github.com/FighterTunnel/packages.git &>/dev/null
    cd
    rm -rf *
}
cek_Trial_mode() {
    until [[ $MYIP =~ ^[0-9.]+$ && ${CLIENT_EXISTS} == '0' ]]; do

        CLIENT_EXISTS=$(wget -qO- https://raw.githubusercontent.com/myridwan/izinvps/ip | grep -w $MYIP | wc -l)
        if [[ ${CLIENT_EXISTS} == '1' ]]; then
            clear
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            echo -e "\e[42m       TRIAL USER TELAH TERSEDIA         \E[0m"
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            echo ""
            echo -e "             ${RED}TIDAK DI IZINKAN${FONT}"
            echo "     MENGGUNAKAN 2 KALI TRIAL MODE"
            echo "UNTUK MELANJUATKAN SILAHKAN REGISTRASI VPS"
            echo ""
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            read -n 1 -s -r -p "       Ketik ENTER untuk Keluar "
            exit 0
        fi
    done
}
cek_reg_mode() {
    until [[ $MYIP =~ ^[0-9.]+$ && ${CLIENT_EXISTS} == '1' ]]; do

        CLIENT_EXISTS=$(wget -qO- https://raw.githubusercontent.com/myridwan/izinvps/ip | grep -w $MYIP | wc -l)
        if [[ ${CLIENT_EXISTS} == '0' ]]; then
            clear
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            echo -e "\e[42m       VPS SERVER TIDAK TERSEDIA         \E[0m"
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            echo ""
            echo -e "             ${RED}TIDAK DI IZINKAN${FONT}"
            echo -e "        VPS SERVER BELUM TERDAPTAR"
            echo "UNTUK MELANJUATKAN SILAHKAN REGISTRASI VPS"
            echo ""
            echo -e "\033[1;93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
            read -n 1 -s -r -p "       Ketik ENTER untuk Keluar "
            exit 0
        fi
    done
}
clear

main() {
    LOGO
    echo -e "  \033[1;91mJANGAN INSTALL SCRIPT INI MENGGUNAKAN KONEKSI VPN!!!${FONT}"
    echo -e ""
    echo -e "${Green}1.${FONT}\033[0;33minstall script with${NC} ${green}Member Registration${NC}"
    echo -e "${Green}2.${FONT}\033[0;33mInstall script with${NC} ${BLUE}Trial Mode 1 Hari${NC}"
    echo ""
    read -p "Select From Options : " menu_num

    case $menu_num in
    1)
        cek_reg_mode
        make_folder_xray
        add_domain
        is_root
        apete_apdet
        install_sc
        ;;
    2)
        cek_Trial_mode
        make_folder_xray
        add_domain
        is_root
        apete_apdet
        Trial_mode
        install_sc
        ;;
    *)
        rm -rf *
        echo -e "${RED}You wrong command !${FONT}"
        ;;
    esac
}
