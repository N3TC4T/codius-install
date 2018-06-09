#!/bin/bash
#
# https://github.com/xrp-community/codius-centos-installer
#
# base tutorial : https://medium.com/codius/how-to-run-your-own-codius-host-42e13afe1fb2
#
# Copyright (c) 2018 XRP Community. Released under the MIT License.
#
# coded by https://twitter.com/baltazar223


set -o nounset
set -o errexit
set -eu

# Functions ==============================================

function coloredEcho(){
    local exp=$1;
    local color=$2;
    if ! [[ $color =~ '^[0-9]$' ]] ; then
       case $(echo $color | tr '[:upper:]' '[:lower:]') in
        black) color=0 ;;
        red) color=1 ;;
        green) color=2 ;;
        yellow) color=3 ;;
        blue) color=4 ;;
        magenta) color=5 ;;
        cyan) color=6 ;;
        white|*) color=7 ;; # white or invalid color
       esac
    fi
    tput setaf $color;
    echo -e $exp;
    tput sgr0;
}

# ============================================== Functions

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi


if [[ -e /etc/debian_version ]]; then
	OS=debian
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
elif [[ -e /etc/arch-release ]]; then
	OS=arch
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu ,CentOS or Arch"
	exit
fi

if [[ $OS != centos ]]; then
  coloredEcho "Sorry but for now just Centos supported!" red
  exit
fi

clear
echo 'Welcome to codius installer!'
echo
echo "I need to ask you a few questions before starting the setup."
echo "You can leave the default options and just press enter if you are ok with them."
echo


# Server Ip Address
echo "[+] First, provide the IPv4 address of the network interface"
# Autodetect IP address and pre-fill for the user
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
read -p "IP address: " -e -i $IP IP
# If $IP is a private IP address, the server must be behind NAT
if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    echo
    echo "This server is behind NAT. What is the public IPv4 address?"
    read -p "Public IP address: " -e PUBLICIP
fi

# Hostname
echo "[+] What is your Codius hostname?"
read -p "Hostname: " -e -i codius.example.com HOSTNAME
if [[ -z "$HOSTNAME" ]]; then
   printf '%s\n' "No Hostname entered , exiting ..."
   exit 1
fi

# Set hostname 
hostnamectl set-hostname $HOSTNAME


# Wallet secret for moneyd
echo "[+] What is your XRP wallet secret (need for moneyd) ?"
read -p "Wallet Secret: " -e SECRET
if [[ -z "$SECRET" ]]; then
   printf '%s\n' "No Secret entered, exiting..."
   exit 1
fi

read -p "[?] Running moneyd in ripple testnet ? [Y/n] " -e TESTNET=${TESTNET:l} #tolower

# Email for certbot
echo "[+] What is your Email address ?"
read -p "Email: " -e EMAIL

if [[ -z "$EMAIL" ]]; then
    printf '%s\n' "No Email entered, exiting..."
    exit 1
fi


# Hyperd ==============================================

coloredEcho "\n[!] Installing required packages ...\n" green
sudo yum install -y gcc-c++ make epel-release git
coloredEcho "\n[!] Installing Hyperd ...\n" green
curl -sSl https://coiltest.s3.amazonaws.com/upload/latest/hyper-bootstrap.sh | bash

# ============================================== Hyperd

# Moneyd ==============================================

coloredEcho "\n[!] Installing Nodejs ...\n" green
curl --silent --location https://rpm.nodesource.com/setup_10.x | sudo bash -
sudo yum install -y nodejs
coloredEcho "\n[!] Installing Moneyd ...\n" green
sudo yum install -y https://s3.us-east-2.amazonaws.com/codius-bucket/moneyd-xrp-4.0.0-1.x86_64.rpm || true


# Configuring moneyd and start service
[ -f /root/.moneyd.json ] && mv /root/.moneyd.json /root/.moneyd.json.back

if [[ $TESTNET =~ ^(yes|y| ) ]] || [[ -z $TESTNET ]]; then
	coloredEcho "\n[!] Configure Moneyd [TESTNET] ...\n" yellow
	echo -ne "$SECRET\n" | /usr/bin/moneyd xrp:configure -t
else
	coloredEcho "\n[!] Configure Moneyd ...\n" yellow
	echo -ne "$SECRET\n" | /usr/bin/moneyd xrp:configure
fi


if pgrep systemd-journal; then
    systemctl restart moneyd-xrp
else
    /etc/init.d/moneyd-xrp restart
fi

# ============================================== Moneyd


# Codius ==============================================

coloredEcho "\n[!] Installing Codius ...\n" green
sudo npm install -g codiusd --unsafe-perm


echo "[Unit]
Description=Codiusd
After=network.target nss-lookup.target
[Service]
ExecStart=/usr/bin/npm start
Environment="DEBUG=*"
Environment="CODIUS_PUBLIC_URI=https://$HOSTNAME"
Environment="CODIUS_XRP_PER_MONTH=10"
WorkingDirectory=/usr/lib/node_modules/codiusd
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=codiusd
User=root
Group=root
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/codiusd.service

if pgrep systemd-journal; then
    systemctl enable codiusd
    systemctl restart codiusd
else
    /etc/init.d/codiusd enable
    /etc/init.d/codiusd restart
fi

# ============================================== Codius

# Subdomain DNS ==============================================
echo
coloredEcho "\n[!] Please create two A records on your DNS and press enter to continue : \n" green
echo "$HOSTNAME.    300     IN      A       $IP
*.$HOSTNAME.  300     IN      A       $IP"

read
while true; do
    ping -c 1 $HOSTNAME >/dev/null 2>&1
    if [ $? -ne 0 ] ; then #if ping exits nonzero...
	coloredEcho "[!] It's look like the host $HOSTNAME is not avalibale yet , waiting 30s ... " red
    else
	coloredEcho "\n[!] Everything looks fine, continuing ... \n" green
	break

    fi
    sleep 30 #check again in SLEEP seconds
done

# ============================================== Subdomain DNS


# CertBOt ==============================================

coloredEcho "\n[+] Generating certificate for ${HOSTNAME}\n" green
# certbot stuff
[ -d certbot ] && rm -rf certbot
git clone https://github.com/certbot/certbot
cd certbot
git checkout v0.23.0
./certbot-auto --noninteractive --os-packages-only
./tools/venv.sh > /dev/null
sudo ln -sf `pwd`/venv/bin/certbot /usr/local/bin/certbot
certbot certonly --manual -d "${HOSTNAME}" -d "*.${HOSTNAME}" --agree-tos --email "${EMAIL}" --preferred-challenges dns-01  --server https://acme-v02.api.letsencrypt.org/directory

# ============================================== CertBOt


# Nginx ==============================================


coloredEcho "\n[!] Installing Nginx ...\n" green
# Nginx
sudo yum install -y nginx

if pgrep systemd-journal; then
    systemctl enable nginx
else
    /etc/init.d/nginx enable
fi

echo 'return 301 https://$host$request_uri;' | sudo tee /etc/nginx/default.d/ssl-redirect.conf
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048


echo "server {
  listen 443 ssl;

  ssl_certificate /etc/letsencrypt/live/$HOSTNAME/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/$HOSTNAME/privkey.pem;

  ssl_protocols TLSv1.2;
  ssl_prefer_server_ciphers on;
  ssl_dhparam /etc/nginx/dhparam.pem;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
  ssl_ecdh_curve secp384r1;
  ssl_session_timeout 10m;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 1.1.1.1 1.0.0.1 valid=300s;
  resolver_timeout 5s;
  add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload';
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;
  add_header X-XSS-Protection '1; mode=block';

location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $$host;
    proxy_set_header X-Forwarded-For $$remote_addr;
  }
}" > /etc/nginx/conf.d/codius.conf


if pgrep systemd-journal; then
    systemctl restart nginx
else
    /etc/init.d/nginx restart
fi

# ============================================== Nginx


coloredEcho "\n[!]Congratulations , it's look like Codius installed successfuly!" green
coloredEcho "\n[-]You can check your Codius with opening $HOSTNAME/version or by visiting the peers list in https://codius.justmoon.com/peers "
coloredEcho "\n[-]Good luck :)"

