#!/bin/bash
sysctl -w net.ipv6.conf.all.disable_ipv6=1 
sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update 
date=$(date -R | cut -d " " -f -5)
scriptku="https://raw.githubusercontent.com/myzid/izin/main/ip"
MYIP=$(wget -qO- ipinfo.io/ip);
date=$(date +"%Y-%m-%d")
clear
red='\e[1;31m'
green='\e[1;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
NC='\e[0m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }


cd /root
#System version number
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi

localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi

# Izin Script
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
checking_sc() {
  useexp=$(wget -qO- $scriptku | grep $IPVPS | awk '{print $3}')
  if [[ $date_list < $useexp ]]; then
    echo -ne
  else
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e "\033[42m          404 NOT FOUND AUTOSCRIPT          \033[0m"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    echo -e ""
    echo -e "            ${RED}PERMISSION DENIED !${NC}"
    echo -e "   \033[0;33mYour VPS${NC} $IPVPS \033[0;33mHas been Banned${NC}"
    echo -e "     \033[0;33mBeli Akses Script Tunneling${NC}"
    echo -e "             \033[0;33mContact Admin :${NC}"
    echo -e "      \033[0;36mTelegram${NC} t.me/fv_stores"
    echo -e "      ${GREEN}WhatsApp${NC} wa.me/6283160098834"
    echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
    exit 0
  fi
}
checking_sc
clear
curl ipinfo.io/org > /root/.isp
curl ipinfo.io/city > /root/.city
curl ipinfo.io/org > /root/.myisp
curl ipinfo.io/city > /root/.mycity
curl ifconfig.me > /root/.ip
curl ipinfo.io/region > /root/.region
curl ifconfig.me > /root/.myip
clear
# USERNAME & EXP
rm -f /usr/bin/user
rm -f /usr/bin/e
username=$(curl ${scriptku} | grep $MYIP | awk '{print $2}')
valid=$(curl ${scriptku} | grep $MYIP | awk '{print $3}')
echo "$username" >/usr/bin/user
echo "$valid" >/usr/bin/e
# DETAIL ORDER
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
# CERTIFICATE STATUS
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""

# Status Expired Or Active 
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl ${scriptku} | grep $MYIP | awk '{print $3}')
if [[ $today < $Exp1 ]]; then
sts="(${green}Active${NC})"
else
sts="(${RED}Expired${NC})"
fi
clear

secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

# Membuat Dictory 
mkdir -p /etc/xray
mkdir -p /etc/v2ray
mkdir -p /etc/cobek
mkdir -p /etc/cobek/limit
mkdir -p /etc/cobek/limit/trojan
mkdir -p /etc/cobek/limit/vless
mkdir -p /etc/cobek/limit/vmess
mkdir -p /etc/cobek/limit/ssh
mkdir -p /etc/cobek/limit/ssh/ip
mkdir -p /etc/cobek/limit/trojan/ip
mkdir -p /etc/cobek/limit/trojan/quota
mkdir -p /etc/cobek/limit/vless/ip
mkdir -p /etc/cobek/limit/vless/quota
mkdir -p /etc/cobek/limit/vmess/ip
mkdir -p /etc/cobek/limit/vmess/quota
mkdir -p /etc/cobek/trojan
mkdir -p /etc/cobek/vless
mkdir -p /etc/cobek/vmess
mkdir -p /etc/cobek/log
mkdir -p /etc/cobek/log/trojan
mkdir -p /etc/cobek/log/vless
mkdir -p /etc/cobek/log/vmess
mkdir -p /etc/cobek/log/ssh
mkdir -p /etc/cobek/cache
mkdir -p /etc/cobek/cache/trojan-tcp
mkdir -p /etc/cobek/cache/trojan-ws
mkdir -p /etc/cobek/cache/trojan-grpc
mkdir -p /etc/cobek/cache/vless-ws
mkdir -p /etc/cobek/cache/vless-grpc
mkdir -p /etc/cobek/cache/vmess-ws
mkdir -p /etc/cobek/cache/vmess-grpc
mkdir -p /etc/cobek/cache/vmess-ws-orbit
mkdir -p /etc/cobek/cache/vmess-ws-orbit1
mkdir -p /var/lib/SIJA >/dev/null 2>&1
echo "IP=" >> /var/lib/SIJA/ipvps.conf
touch /etc/xray/domain
touch /etc/v2ray/domain
touch /etc/xray/scdomain
touch /etc/v2ray/scdomain

# Install Paket Yg Dibutuhkan
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt install sudo -y
sudo apt-get clean all
sudo apt-get install -y debconf-utils
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt-get autoremove -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y iptables iptables-persistent netfilter-persistent figlet ruby php php-fpm php-cli php-mysql libxml-parser-perl squid nmap screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools sed gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch lsof openssl openvpn easy-rsa fail2ban tmux stunnel4 squid3 dropbear socat cron bash-completion ntpdate xz-utils apt-transport-https gnupg2 dnsutils lsb-release chrony libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev xl2tpd pptpd apt git speedtest-cli p7zip-full
sudo apt-get install -y libjpeg-dev zlib1g-dev python python3 python3-pip shc build-essential speedtest-cli p7zip-full nodejs nginx
apt install nginx -y
apt install wget -y
apt install curl -y
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
apt install -y bzip2 gzip coreutils screen curl unzip
sudo apt-get autoclean -y >/dev/null 2>&1
audo apt-get -y --purge removd unscd >/dev/null 2>&1
sudo apt-get -y --purge remove samba* >/dev/null 2>&1
sudo apt-get -y --purge remove apache2* >/dev/null 2>&1
sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
sudo apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
# Install Vnstat
sudo apt-get -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6

# Gotop & Swap
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
        # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    wget https://raw.githubusercontent.com/FadlyNotNot/v1/main/bbr.sh ; chmod +x bbr.sh ; ./bbr.sh
    rm -rf bbr.sh

clear
# Setup Domain
echo -e "$green━━━━━━━━━━┏┓━━━━━━━━━━━━━━━━━━━━━━━━┏┓━━━━━━━━━━━$NC"
echo -e "$green━━━━━━━━━┏┛┗┓━━━━━━━━━━━━━━━━━━━━━━┏┛┗┓━━━━━━━━━━$NC"
echo -e "$green┏━━┓━┏┓┏┓┗┓┏┛┏━━┓━━━━┏━━┓┏━━┓┏┓┏━┓━┗┓┏┛┏┓┏━┓━┏━━┓$NC"
echo -e "$green┗━┓┃━┃┃┃┃━┃┃━┃┏┓┃━━━━┃┏┓┃┃┏┓┃┣┫┃┏┓┓━┃┃━┣┫┃┏┓┓┃┏┓┃$NC"
echo -e "$green┃┗┛┗┓┃┗┛┃━┃┗┓┃┗┛┃━━━━┃┗┛┃┃┗┛┃┃┃┃┃┃┃━┃┗┓┃┃┃┃┃┃┃┗┛┃$NC"
echo -e "$green┗━━━┛┗━━┛━┗━┛┗━━┛━━━━┃┏━┛┗━━┛┗┛┗┛┗┛━┗━┛┗┛┗┛┗┛┗━┓┃$NC"
echo -e "$green━━━━━━━━━━━━━━━━━━━━━┃┃━━━━━━━━━━━━━━━━━━━━━━┏━┛┃$NC"
echo -e "$green━━━━━━━━━━━━━━━━━━━━━┗┛━━━━━━━━━━━━━━━━━━━━━━┗━━┛$NC"
echo -e "$BBlue                     SETUP DOMAIN VPS     $NC"
echo -e "$BYellow----------------------------------------------------------$NC"
echo -e "$BGreen 1. Use Domain Random / Menggunakan Domain Random $NC"
echo -e "$BGreen 2. Choose Your Own Domain / Menggunakan Domain Sendiri $NC"
echo -e "$BYellow----------------------------------------------------------$NC"
read -rp " Choose Potions 1 or 2 / pilih 1 atau 2 : " dns
	if test $dns -eq 1; then
    clear
    apt install jq curl -y
    wget -q -O /root/cf "https://raw.githubusercontent.com/myzid/vvip/main/ssh/cf" >/dev/null 2>&1
    chmod +x /root/cf
    bash /root/cf | tee /root/install.log
	elif test $dns -eq 2; then
    clear
    echo -e " \e[1;33mSEBELUM MEMASUKAN DOMAIN, HARAP POINTING DULU IP VPS KAMU !\e[0m"
    echo ""
    read -rp "Masukan Domain Kamu : " pp
    echo "$pp" > /root/scdomain
	echo "$pp" > /etc/xray/scdomain
	echo "$pp" > /etc/xray/domain
	echo "$pp" > /etc/v2ray/domain
	echo "$pp" > /root/domain
    echo "IP=$pp" > /var/lib/SIJA/ipvps.conf
    fi

    tgl2=$(date +"%d")
    bln2=$(date +"%b")
    thn2=$(date +"%Y")
    tnggl="$tgl2 $bln2, $thn2"
    MYIP=$(curl -sS ipv4.icanhazip.com)
    domain=$(cat /etc/xray/domain)
    CHATID="-1001899398362"
    KEY="6293396608:AAGqZVrmdQjPc3tOj_gnUoWOVMrBsm8v6Xo"
    TIMES="10"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
    <code>────────────────────</code>
    <b>⚡AUTOSCRIPT PREMIUM⚡</b>
    <code>────────────────────</code>
    <code>ID     : </code><code>$username</code>
    <code>Domain : </code><code>$domain</code>
    <code>Date   : </code><code>$tnggl</code>
    <code>Time   : </code><code>$TIMEZONE</code>
    <code>Ip vps : </code><code>$MYIP</code>
    <code>Exp Sc : </code><code>$exp</code>
    <code>────────────────────</code>
    <i>Automatic Notification from Github</i>
    "'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ🧊","url":"https://t.me/fv_stores"},{"text":"ᴏʀᴅᴇʀ🧊","url":"wa.me/083160098834"}]]}'
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

clear 
#install ssh & ws python
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m            Install SSH WS          \E[0m$NC"
echo -e "─────────────────────────────────────────"
sleep 3
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/install/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/sshws/insshws.sh && chmod +x insshws.sh && ./insshws.sh
clear
#install ins-xray
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install Xray          \E[0m$NC"
echo -e "─────────────────────────────────────────"
sleep 3
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/install/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
#install menu
clear
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install Menu          \E[0m$NC"
echo -e "─────────────────────────────────────────"
sleep 3
clear
rm -rf /tmp/menu
wget -O /tmp/menu.zip "https://raw.githubusercontent.com/myzid/vvip/main/menu/project.zip" >/dev/null 2>&1
    mkdir /tmp/menu
    7z e -pFadlyvpnprojek213 /tmp/menu.zip -o/tmp/menu/ >/dev/null 2>&1
    chmod +x /tmp/menu/*
    mv /tmp/menu/* /usr/local/sbin/

rm -rf /root/menu
rm -rf menu.zip
clear
#install br
echo -e "─────────────────────────────────────────"
echo -e " \E[41;1;97m              Install BCKP          \E[0m$NC"
echo -e "─────────────────────────────────────────"
sleep 5 
clear 
wget https://raw.githubusercontent.com/myzid/vvip/main/backup/set-br.sh && chmod +x set-br.sh && ./set-br.sh
clear
# // Download Data
echo -e "${GREEN}Download Data${NC}"
wget -q -O /usr/bin/acs-set "https://raw.githubusercontent.com/myzid/vvip/main/acs-set.sh"
cd /usr/bin
wget -q -O /usr/bin/loop "https://raw.githubusercontent.com/myzid/vvip/main/limit/loop.sh"
wget -q -O /usr/bin/matikan "https://raw.githubusercontent.com/myzid/vvip/main/limit/matikan.sh"
wget -q -O /usr/bin/limit "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit.sh"
wget -q -O /usr/bin/limit-ip-ssh "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-ip-ssh.sh"
wget -q -O /usr/bin/limit-ip-trojan "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-ip-trojan.sh"
wget -q -O /usr/bin/limit-ip-vless "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-ip-vless.sh"
wget -q -O /usr/bin/limit-ip-vmess "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-ip-vmess.sh"
wget -q -O /usr/bin/limit-quota-trojan "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-quota-trojan.sh"
wget -q -O /usr/bin/limit-quota-vmess "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-quota-vmess.sh"
wget -q -O /usr/bin/limit-quota-vless "https://raw.githubusercontent.com/myzid/vvip/main/limit/limit-quota-vless.sh"
wget -q -O /usr/bin/quota "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota.sh"
wget -q -O /usr/bin/quota-trojan-grpc "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-trojan-grpc.sh"
wget -q -O /usr/bin/quota-trojan-ws "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-trojan-ws.sh"
wget -q -O /usr/bin/quota-vmess-grpc "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vmess-grpc.sh"
wget -q -O /usr/bin/quota-vmess-ws "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vmess-ws.sh"
wget -q -O /usr/bin/quota-vless-ws "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vless-ws.sh"
wget -q -O /usr/bin/quota-vless-grpc "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vless-grpc.sh"
wget -q -O /usr/bin/quota-vmess-orbit "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vmess-ws-orbit.sh"
wget -q -O /usr/bin/quota-vmess-orbit1 "https://raw.githubusercontent.com/myzid/vvip/main/limit/quota-vmess-ws-orbit1.sh"
chmod +x /usr/bin/*
cd 
chmod +x /usr/bin/acs-set

clear
# Default Menu
sleep 2
cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /etc/cron.d/cl_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 1 * * * root /usr/bin/clearlog
END

cat > /home/re_otm <<-END
7
END

clear
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
neofetch
END
chmod 644 /root/.profile
clear

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1

if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi
history -c
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
curl -sS ifconfig.me > /etc/myipvps
clear
echo ""
echo "------------------------------------------------------------"
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH		: 22"  | tee -a log-install.txt
echo "   - SSH Websocket	: 80, 8080, 8880, 2082" | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4		: 447, 777" | tee -a log-install.txt
echo "   - Dropbear		: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7300" | tee -a log-install.txt
echo "   - Nginx		: 81" | tee -a log-install.txt
echo "   - Vmess    		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS       : 80, 8080, 8880, 2082" | tee -a log-install.log
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80, 8080, 8880, 2082" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS TLS	: 443" | tee -a log-install.txt
echo "   - Trojan WS NTLS	: 80, 8080, 8880, 2082" | tee -a log-install.txt
echo "   - Trojan Go		: 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone		: Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban		: [ON]"  | tee -a log-install.txt
echo "   - Dflate		: [ON]"  | tee -a log-install.txt
echo "   - IPtables		: [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot		: [ON]"  | tee -a log-install.txt
echo "   - IPv6			: [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On	: $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "------------------------------------------------------------"
echo ""
echo "" | tee -a log-install.txt
rm /root/limit >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm /root/udp.sh >/dev/null 2>&1
rm /root/cf >/dev/null 2>&1
touch /root/.system 
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e ""
history -c
read -n 1 -s -r -p "Pencet [ Enter ] Untuk Reboot"
reboot
