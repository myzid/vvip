#!/bin/bash
sysctl -w net.ipv6.conf.all.disable_ipv6=1 
sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update 
date=$(date -R | cut -d " " -f -5)
IP=$(wget -qO- ipinfo.io/ip);
domain=$(cat /etc/xray/domain)
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

echo
  read -p "[ ${green}NOTES${NC} ] Untuk Melanjutkan Penginstallan Klik Enter ! "
  sleep 3
  echo -e "[ ${green}INFO${NC} ] Oke, Melanjutkan Penginstallan"


secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

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

wget -q https://raw.githubusercontent.com/myzid/vvip/main/tools.sh && chmod +x tools.sh && ./tools.sh
rm tools.sh
apt install wget -y
apt install curl -y
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
apt install -y bzip2 gzip coreutils screen curl unzip

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

clear
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
read -rp " input 1 or 2 / pilih 1 atau 2 : " dns
	if test $dns -eq 1; then
    clear
    apt install jq curl -y
    wget -q -O /root/cf "https://raw.githubusercontent.com/myzid/vvip/main/ssh/cf" >/dev/null 2>&1
    chmod +x /root/cf
    bash /root/cf | tee /root/install.log
	elif test $dns -eq 2; then
    read -rp "Masukan Domain Kamu : " pp
    echo "$pp" > /root/scdomain
	echo "$pp" > /etc/xray/scdomain
	echo "$pp" > /etc/xray/domain
	echo "$pp" > /etc/v2ray/domain
	echo "$pp" > /root/domain
    echo "IP=$pp" > /var/lib/SIJA/ipvps.conf
    fi

clear 
#install ssh-vpn
echo -e "┌─────────────────────────────────────────┐"
echo -e " \E[41;1;97m         >>> Install SSH WS <<<         \E[0m$NC"
echo -e "└─────────────────────────────────────────┘"
sleep 3
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/sshws/insshws.sh && chmod +x insshws.sh && ./insshws.sh
#install ins-xray
echo -e "┌─────────────────────────────────────────┐"
echo -e " \E[41;1;97m           >>> Install Xray <<<          \E[0m$NC"
echo -e "└─────────────────────────────────────────┘"
sleep 3
clear
wget https://raw.githubusercontent.com/myzid/vvip/main/xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
#install menu
clear
echo -e "┌─────────────────────────────────────────┐"
echo -e " \E[41;1;97m           >>> Install Menu <<<          \E[0m$NC"
echo -e "└─────────────────────────────────────────┘"
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
echo -e "┌─────────────────────────────────────────┐"
echo -e " \E[41;1;97m           >>> Install BR <<<            \E[0m$NC"
echo -e "└─────────────────────────────────────────┘"
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

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1

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
echo " "
echo "------------------------------------------------------------"
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH		: 22"  | tee -a log-install.txt
echo "   - SSH Websocket	: 80, 8880, 2082" | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4		: 447, 777" | tee -a log-install.txt
echo "   - Dropbear		: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7900" | tee -a log-install.txt
echo "   - Nginx		: 81" | tee -a log-install.txt
echo "   - Vmess TLS		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS	: 80" | tee -a log-install.txt
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS		: 443" | tee -a log-install.txt
echo "   - Trojan Go		: 443" | tee -a log-install.txt
echo "   - slowdns              : 443,80,8080,53,5300" | tee -a log-install.txt
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
echo ""
echo "------------------------------------------------------------"
echo ""
echo "" | tee -a log-install.txt
rm /root/limit >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
touch /root/.system 
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e "
"
read -n 1 -s -r -p "Pencet [ Enter ] Untuk Reboot"
reboot
