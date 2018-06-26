#!/bin/bash
# File              : codius-install.sh
# Author            : N3TC4T <netcat.av@gmail.com>
# Date              : 16.06.2018
# Last Modified Date: 25.06.2018
# Last Modified By  : N3TC4T <netcat.av@gmail.com>
# Copyright (c) 2018 N3TC4T <netcat.av@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e

########## Variable ##########
SUDO=""
SLEEP_SEC=10
LOG_OUTPUT="/tmp/${0##*/}$(date +%Y-%m-%d.%H-%M)" 
CURRENT_USER="$(id -un 2>/dev/null || true)"
BASE_DIR=$(cd "$(dirname "$0")"; pwd); cd ${BASE_DIR}
########## Hyperd ##########
HYPERD_URL="https://codius-hyper-install.s3.amazonaws.com/hyper-bootstrap.sh"
########## Nodejs ##########
NODEJS_RPM_URL="https://rpm.nodesource.com/setup_10.x"
NODEJS_DEB_URL="https://deb.nodesource.com/setup_10.x"
YARN_URL="https://yarnpkg.com/install.sh"
########## Certbot ##########
CERTBOT_AUTO_URL="https://dl.eff.org/certbot-auto"
########## Constant ##########
SUPPORT_DISTRO=(debian ubuntu fedora centos)
UBUNTU_CODE=(trusty utopic vivid wily xenial)
DEBIAN_CODE=(jessie wheezy)
CENTOS_VER=(6 7)
FEDORA_VER=(20 21 22 23 24 25)
#Color Constant
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
WHITE=`tput setaf 7`
LIGHT=`tput bold `
RESET=`tput sgr0`
#Error Message#Error Message
ERR_ROOT_PRIVILEGE_REQUIRED=(10 "This install script need root privilege, please retry use 'sudo' or root user!")
ERR_NOT_SUPPORT_PLATFORM=(20 "Sorry, Hyperd only support x86_64 platform!")
ERR_NOT_SUPPORT_DISTRO=(21 "Sorry, The installer only support centos now due the hyper package limitations!")
ERR_NOT_PUBLIC_IP=(11 "You need an public IP to run Codius!")
ERR_NOT_SUPPORT_DISTRO_VERSION=(22)
ERR_SCRIPT_NO_NEW_VERSION=(80 "You are using the newest codius installer\n")
ERR_NO_CERTBOT_INSTALLED=(81 "Certbot is not installed!\n")
ERR_UNKNOWN_MSG_TYPE=98
ERR_UNKNOWN=99
# Helpers ==============================================

display_header()
{
cat <<"EOF"

     ____          _ _             ___           _        _ _           
    / ___|___   __| (_)_   _ ___  |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
   | |   / _ \ / _` | | | | / __|  | || '_ \/ __| __/ _` | | |/ _ \ '__|
   | |__| (_) | (_| | | |_| \__ \  | || | | \__ \ || (_| | | |  __/ |   
    \____\___/ \__,_|_|\__,_|___/ |___|_| |_|___/\__\__,_|_|_|\___|_|   


This script will let you setup your own codius peer in no more than two minute,
even if you haven't used codius before. 
It has been designed to be as unobtrusive and universal as possible.

EOF
}

_box () {
    str="$@"
    len=$((${#str}+4))
    for i in $(seq $len); do echo -n '.'; done;
    echo; echo ". "$str" .";
    for i in $(seq $len); do echo -n '.'; done;
    echo
}

function spin_wait() { 
  local -r SPIN_DELAY="0.1"
  local spinstr="⠏⠛⠹⠼⠶⠧"
  printf "  "
  while kill -0 $1 2>/dev/random; do
    local tmp=${spinstr#?}

    if [ -z "$2" ]; then
        printf " \b\b\b${tmp:0:1} "
    else
        printf "${cl} ${tmp:0:1} ${2}"
    fi

    local spinstr=$tmp${spinstr%"$tmp"}
    sleep ${SPIN_DELAY}
  done
  printf "\033[3D\033[K ${LIGHT}${GREEN}Done${RESET}"
  # printf "\r\033[K"
}

function _exec() {
  local -i PID=
  local COMMAND=$1
  shift      ## Clip the first value of the $@, the rest are the options. 
  local COMMAND_OPTIONS="$@"
  local COMMAND_OUTPUT=""
  echo -e "\n==================================" >> "${LOG_OUTPUT}"
  echo "${COMMAND} $COMMAND_OPTIONS" >> "${LOG_OUTPUT}"
  echo -e "==================================\n" >> "${LOG_OUTPUT}"
  exec 3>$(tty)
  eval "time ${SUDO} bash -c '${COMMAND} ${COMMAND_OPTIONS}'" >>"${LOG_OUTPUT}" 2>&1  &
  PID=$! # Set global PGID to process id of the command we just ran. 
  spin_wait "${PID}"
  exec 3>&-
}

function program_is_installed {
  # set to 1 initially
  local return_=1
  # set to 0 if not found
  type $1 >/dev/null 2>&1 || { local return_=0; }
  # return value
  echo "$return_"
}

function service_is_running {
  # set to 1 initially
  local return_=0
  # set to 0 if not found
  if (( $(ps -ef | grep -v grep | grep $1 | wc -l) > 0 )) ;then
    local return_=1
  fi
  # return value
  echo "$return_"
}

function echo_if {
  if [ $1 == 1 ]; then
    echo -e "${LIGHT}${GREEN}✔ ${RESET}"
  else
    echo -e "${RED}✘${RESET}"
  fi
}

new_line() { printf "\n"; }

show_message() {
  case "$1" in
    debug)  echo -e "\n[${BLUE}DEBUG${RESET}] : $2";;
    info)   echo -e -n "\n${WHITE}$2${RESET}" ;;
    warn)   echo -e    "\n[${YELLOW}WARN${RESET}] : $2" ;;
    done|success) echo -e "${LIGHT}${GREEN}$2${RESET}" ;;
    error|failed) echo -e "\n[${RED}ERROR${RESET}] : $2" ;;
  esac
}

command_exist() {
  type "$@" > /dev/null 2>&1
}


get_curl() {
  CURL_C=""; USE_WGET="false"
  if (command_exist curl);then
    CURL_C='curl -SL -o '
  elif (command_exist wget);then
    USE_WGET="true"
    CURL_C='wget -O '
  fi

  echo "${USE_WGET}|${CURL_C}"
}

check_os_platform() {
  ARCH="$(uname -m)"
  if [[ "${ARCH}" != "x86_64" ]];then
    show_message error "${ERR_NOT_SUPPORT_PLATFORM[1]}" && exit ${ERR_NOT_SUPPORT_PLATFORM[0]}
  fi
}
check_deps_initsystem() {
  if [[ "${LSB_DISTRO}" == "ubuntu" ]] && [[ "${LSB_CODE}" == "utopic" ]];then
    INIT_SYSTEM="sysvinit"
  elif (command_exist systemctl);then
    INIT_SYSTEM="systemd"
  else
    INIT_SYSTEM="sysvinit"
  fi
}

check_os_distro() {
  LSB_DISTRO=""; LSB_VER=""; LSB_CODE=""
  if (command_exist lsb_release);then
    LSB_DISTRO="$(lsb_release -si)"
    LSB_VER="$(lsb_release -sr)"
    LSB_CODE="$(lsb_release -sc)"
  fi
  if [[ -z "${LSB_DISTRO}" ]];then
    if [[ -r /etc/lsb-release ]];then
      LSB_DISTRO="$(. /etc/lsb-release && echo "${DISTRIB_ID}")"
      LSB_VER="$(. /etc/lsb-release && echo "${DISTRIB_RELEASE}")"
      LSB_CODE="$(. /etc/lsb-release && echo "${DISTRIB_CODENAME}")"
    elif [[ -r /etc/os-release ]];then
      LSB_DISTRO="$(. /etc/os-release && echo "$ID")"
      LSB_VER="$(. /etc/os-release && echo "$VERSION_ID")"
    elif [[ -r /etc/fedora-release ]];then
      LSB_DISTRO="fedora"
    elif [[ -r /etc/debian_version ]];then
      LSB_DISTRO="Debian"
      LSB_VER="$(cat /etc/debian_version)"
    elif [[ -r /etc/centos-release ]];then
      LSB_DISTRO="CentOS"
      LSB_VER="$(cat /etc/centos-release | cut -d' ' -f3)"
    fi
  fi
  LSB_DISTRO=$(echo "${LSB_DISTRO}" | tr '[:upper:]' '[:lower:]')
  if [[ "${LSB_DISTRO}" == "debian" ]];then
    case ${LSB_VER} in
      8) LSB_CODE="jessie";;
      7) LSB_CODE="wheezy";;
    esac
  fi

  case "${LSB_DISTRO}" in
    ubuntu|debian)
      if [[ "${LSB_DISTRO}" == "ubuntu" ]]
      then SUPPORT_CODE_LIST="${UBUNTU_CODE[@]}";
      else SUPPORT_CODE_LIST="${DEBIAN_CODE[@]}";
      fi
      if (echo "${SUPPORT_CODE_LIST}" | grep -vqw "${LSB_CODE}");then
        show_message error "Hyper support ${LSB_DISTRO}( ${SUPPORT_CODE_LIST} ), but current is ${LSB_CODE}(${LSB_VER})"
        exit ${ERR_NOT_SUPPORT_DISTRO_VERSION[0]}
      fi
    ;;
    centos|fedora)
      CMAJOR=$( echo ${LSB_VER} | cut -d"." -f1 )
      if [[  "${LSB_DISTRO}" == "centos" ]]
      then SUPPORT_VER_LIST="${CENTOS_VER[@]}";
      else SUPPORT_VER_LIST="${FEDORA_VER[@]}";
      fi
      if (echo "${SUPPORT_VER_LIST}" | grep -qvw "${CMAJOR}");then
        show_message error "Hyper support ${LSB_DISTRO}( ${SUPPORT_VER_LIST} ), but current is ${LSB_VER}"
        exit ${ERR_NOT_SUPPORT_DISTRO_VERSION[0]}
      fi
    ;;
    *) if [[ ! -z ${LSB_DISTRO} ]];then echo -e -n "\nCurrent OS is '${LSB_DISTRO} ${LSB_VER}(${LSB_CODE})'";
       else echo -e -n "\nCan not detect OS type"; fi
      show_message error "${ERR_NOT_SUPPORT_DISTRO[1]}"
      exit ${ERR_NOT_SUPPORT_DISTRO[0]}
    ;;
  esac
}

check_user() {
  if [[ "${CURRENT_USER}" != "root" ]];then
    if (command_exist sudo);then
      SUDO='sudo'
    else
      show_message error "${ERR_ROOT_PRIVILEGE_REQUIRED[1]}" && exit ${ERR_ROOT_PRIVILEGE_REQUIRED[0]}
    fi
    show_message info "${WHITE}Hint: This installer need root privilege\n"
    ${SUDO} echo -e "\n"
  fi
}


# ============================================== Helpers


################### INSTALL ###########################

install()
{

  local USE_WGET=$( echo $(get_curl) | awk -F"|" '{print $1}' )
  local CURL_C=$( echo $(get_curl) | awk -F"|" '{print $2}' )

  new_line
  show_message info "[-] I need to ask you a few questions before starting the setup."
  show_message info "[-] You can leave the default options and just press enter if you are ok with them."
  new_line
  new_line

  # checks for script
  check_user
  check_os_platform
  check_os_distro
  check_deps_initsystem



  # Server Ip Address
  echo "[+] First, provide the IPv4 address of the network interface"
  # Autodetect IP address and pre-fill for the user
  IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
  read -p "IP address: " -e -i $IP IP
  # If $IP is a private IP address, the server must be behind NAT
  if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    show_message error "${ERR_NOT_PUBLIC_IP[1]}"
    exit "${ERR_NOT_PUBLIC_IP[0]}"
  fi

  # Hostname
  echo "[+] What is your Codius hostname ?"
  read -p "Hostname: " -e -i codius.example.com HOSTNAME
  if [[ -z "$HOSTNAME" ]]; then
    show_message error "No Hostname entered , exiting ..."
    exit 0
  fi

  # Wallet secret for moneyd
  echo "[+] What is your XRP wallet secret (need for moneyd) ?"

  while true; do
    read -p "Wallet Secret: " -e SECRET
    if [[ -z "$SECRET" ]] || ! [[ "$SECRET" =~ ^s[a-zA-Z0-9]{28,}+$ ]] ; then
      show_message error "Invalid Secret entered, try again... "
    else
      break
    fi
  done


  # Email for certbot
  echo "[+] What is your Email address ?"
  while true; do
    read -p "Email: " -e EMAIL

    if [[ -z "$EMAIL" ]] || ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
        show_message error "Invalid Email entered, try again..."
    else
      break
    fi
  done


  show_message debug "Setting hostname using 'hostnamectl'"
  # Set hostname
  ${SUDO} hostnamectl set-hostname $HOSTNAME


  # Repositories and required packages ====================================

  show_message info "[+] Installing required packages... "

  if [[ "${LSB_DISTRO}" == "centos" ]] && [[ "${CMAJOR}" == "7" ]];then
    _exec "rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm ; yum install -y gcc-c++ make epel-release git"
  elif [[ "${LSB_DISTRO}" == "centos" ]] && [[ "${CMAJOR}" == "6" ]];then
    _exec "rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm ; yum install -y gcc-c++ make epel-release git"
  elif [[ "${LSB_DISTRO}" == "ubuntu" ]];then
    _exec "apt-get install -y software-properties-common ; add-apt-repository ppa:certbot/certbot ; apt-get install -y build-essential git qemu-kvm libvirt0 aufs-tools"
  elif [[ "${LSB_DISTRO}" == "debian" ]];then
    _exec "apt-get update ; apt-get install -y build-essential git qemu-kvm libvirt0 aufs-tools"
  fi


  # Hyperd ==============================================

  show_message info "[+] Installing Hyperd... "

  ${SUDO} ${CURL_C} /tmp/hyper-bootstrap.sh ${HYPERD_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /tmp/hyper-bootstrap.sh

  _exec bash /tmp/hyper-bootstrap.sh

  show_message info "[*] Starting Hyperd... "

  if [[ "${INIT_SYSTEM}" == "systemd" ]];then
    _exec "systemctl enable hyperd; systemctl restart hyperd"
  else
    _exec "service hyperd enable; service hyperd restart"
  fi


  # ============================================== Hyperd

  # Nodejs ==============================================

  show_message info "[+] Installing Nodejs... "


  if [[ "${LSB_DISTRO}" == "centos"  ]] || [[ "${LSB_DISTRO}" == "fedora"  ]] ;then
    ${SUDO} ${CURL_C} /tmp/nodejs_10.sh ${NODEJS_RPM_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /tmp/nodejs_10.sh
    _exec "bash /tmp/nodejs_10.sh && yum install -y nodejs"
  elif [[ "${LSB_DISTRO}" == "ubuntu" ]] || [[ "${LSB_DISTRO}" == "debian" ]] ;then
    ${SUDO} ${CURL_C} /tmp/nodejs_10.sh ${NODEJS_DEB_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /tmp/nodejs_10.sh
    _exec "bash /tmp/nodejs_10.sh && apt-get install -y nodejs"
  fi




  # yarn ==============================================


  show_message info "[+] Installing Yarn... "

  ${SUDO} ${CURL_C} /tmp/yarn_installer.sh ${YARN_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /tmp/yarn_installer.sh

  _exec bash /tmp/yarn_installer.sh

  # fix for yarn command not found
  export PATH="$HOME/.yarn/bin:$HOME/.config/yarn/global/node_modules/.bin:$PATH"

  # ============================================== Nodejs

  # Moneyd ==============================================

  show_message info "[+] Installing Moneyd... "
  # _exec yum install -y https://s3.us-east-2.amazonaws.com/codius-bucket/moneyd-xrp-4.0.0-1.x86_64.rpm
  _exec yarn global add moneyd moneyd-uplink-xrp

  ${SUDO} echo '[Unit]
Description=ILP provider using XRP payment channels
After=network.target nss-lookup.target

[Service]
ExecStart=/usr/local/bin/moneyd xrp:start
Environment="DEBUG=*"
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=moneyd
User=root
Group=root

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/moneyd-xrp.service


  # Configuring moneyd and start service
  if [ -f ~/.moneyd.json ]; then
    show_message warn "Old ~/.moneyd.json config file found , backup to ~/.moneyd.json.back"
    ${SUDO} mv ~/.moneyd.json ~/.moneyd.json.back
  fi

  echo -ne "$SECRET\n" | /usr/local/bin/moneyd xrp:configure > /dev/null 2>&1

  show_message info "[*] Starting Moneyd... "

  if [[ "${INIT_SYSTEM}" == "systemd" ]];then
    _exec "systemctl enable moneyd-xrp ; systemctl restart moneyd-xrp"
  else
    _exec "service moneyd-xrp enable; service moneyd-xrp restart"
  fi


  # ============================================== Moneyd


  # Codius ==============================================

  show_message info "[+] Installing Codius... "
  _exec yarn global add codiusd

  ${SUDO} echo "[Unit]
Description=Codiusd
After=network.target nss-lookup.target
[Service]
ExecStart=/usr/local/bin/codiusd
Environment="DEBUG=*"
Environment="CODIUS_PUBLIC_URI=https://$HOSTNAME"
Environment="CODIUS_XRP_PER_MONTH=10"
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=codiusd
User=root
Group=root
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/codiusd.service

  show_message info "[*] Starting Codius... "

  if [[ "${INIT_SYSTEM}" == "systemd" ]];then
    _exec "systemctl enable codiusd ; systemctl restart codiusd"
  else 
    _exec "service codiusd enable ; service codiusd restart"
  fi


  # ============================================== Codius

  # Subdomain DNS ==============================================
  new_line
  show_message info "[+] Please create two A records as below on your DNS :"
  new_line
  cat <<EOF
------------------------------------------------------------

$HOSTNAME.    300     IN      A       $IP
*.$HOSTNAME.  300     IN      A       $IP

------------------------------------------------------------
EOF

  read -n1 -r -p "Press any key to continue..."

  while true; do
    if ping -c1 -W1 $HOSTNAME &> /dev/null; then
      break
    else
      show_message warn "It's look like the $HOSTNAME cannot be resolved yet , waiting 30s ... "
    fi
    sleep 30 #check again in SLEEP seconds
  done

  # ============================================== Subdomain DNS


  # CertBOt ==============================================
  show_message info "[+] Generating certificate for ${HOSTNAME}"
  # certbot stuff

  show_message info "[+] Installing CertBot... "
  if [[ "${LSB_DISTRO}" == "centos"  ]] || [[ "${LSB_DISTRO}" == "fedora"  ]] ;then
    _exec "yum -y install certbot"
  elif [[ "${LSB_DISTRO}" == "ubuntu" ]];then
    _exec "apt-get install -y certbot"
  elif [[ "${LSB_DISTRO}" == "debian" ]];then
    ${SUDO} ${CURL_C} /usr/bin/certbot ${CERTBOT_AUTO_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /usr/bin/certbot
    _exec "/usr/bin/certbot"
  fi

  new_line
  show_message warn "In next step you need to create two TXT challenges record on your DNS \nPlease don't forget to wait some minute after creating records! "
  read -n1 -r -p "Press any key to continue ..."

  # if [[ "${USE_WGET}" == "true" ]];then
  #       ${CURL_C} -O /usr/sbin/certbot-auto ${CERTBOT_URL} >>"${LOG_OUTPUT}" 2>&1 && chmod a+x /usr/sbin/certbot-auto
  # else
  #       ${CURL_C} /usr/sbin/certbot-auto ${NODEJS_URL} >>"${LOG_OUTPUT}" 2>&1 && chmod a+x /usr/sbin/certbot-auto
  # fi

  # certbot-auto --noninteractive --os-packages-only

  ${SUDO} certbot certonly --manual -d "${HOSTNAME}" -d "*.${HOSTNAME}" --agree-tos --email "${EMAIL}" --preferred-challenges dns-01  --server https://acme-v02.api.letsencrypt.org/directory

  # ============================================== CertBOt


  # Nginx ==============================================

  show_message info "[!] Installing Nginx... "


  if [[ "${LSB_DISTRO}" == "centos"  ]] || [[ "${LSB_DISTRO}" == "fedora"  ]] ;then
    # Install Package
    # Selinux allow nginx
    # Enable access for port 443 in firewalld
    _exec "yum -y install nginx ; setsebool -P httpd_can_network_connect 1 ; firewall-cmd --zone=public --add-port=443/tcp --permanent"

  elif [[ "${LSB_DISTRO}" == "ubuntu" ]] || [[ "${LSB_DISTRO}" == "debian" ]] ;then
    # Install Package
    # Adjust the Firewall
    _exec "apt-get install -y nginx ; ufw allow 'Nginx HTTP'"

  fi

  # show_message done "[!] Success Installed Nginx"

  if [[ ! -e /etc/nginx/default.d ]]; then
	  ${SUDO} mkdir /etc/nginx/default.d
  fi

  ${SUDO} echo 'return 301 https://$host$request_uri;' | ${SUDO} tee /etc/nginx/default.d/ssl-redirect.conf >> "${LOG_OUTPUT}" 2>&1

  show_message info "[!] Generating SSL file (it's take a while , don't panic)... "

  _exec openssl dhparam -out /etc/nginx/dhparam.pem 2048


  if [[ ! -e /etc/nginx/conf.d ]]; then
	  ${SUDO} mkdir /etc/nginx/conf.d
  fi

  ${SUDO} echo "
server {
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
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-For \$remote_addr;
    }
}" > /etc/nginx/conf.d/codius.conf

  show_message info "[*] Starting Nginx... "

  if [[ "${INIT_SYSTEM}" == "systemd" ]];then
    _exec "systemctl enable nginx ; systemctl restart nginx"
  else
    _exec "service nginx enable ; service nginx restart"
  fi

  # ============================================== Nginx


  # ============================================== Finishing
  new_line
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =
  new_line
  show_message done "[!] Congratulations , it's look like Codius installed successfuly!"
  new_line
  show_message done "[-] You can check your Codius with opening https://$HOSTNAME/version or by visiting the peers list in https://$HOSTNAME/peers "
  show_message done "[-] For installation log visit $LOG_OUTPUT"
  new_line
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =


  new_line
  show_message warn "If you have problem in opening the Codius it's recommended to reboot your system in order to complate the installation proccess ..."
  new_line
  read -p "Reboot now? [y/N]: " -e REBOOT

  if [[ "$REBOOT" = 'y' || "$REBOOT" = 'Y' ]]; then
      echo "Rebooting ..."
      ${SUDO} reboot
  else
    exit
  fi
}



################### UPDATE ###########################

update()
{
  check_deps_initsystem
  # We need to check if moneyd installed with one of NPM or Yarn

  local PACKAGES=(moneyd codiusd)
  local PACKAGE_MANAGER=

  show_message info "[-] Checking packages availability ..."
  for package in "${PACKAGES[@]}"
  do
    local FOUND_IN_YARN=0
    local FOUND_IN_NPM=0
    # check if moneyd installed with NPM
    npm list --depth 0 --global "$package" > /dev/null 2>&1 && { local FOUND_IN_NPM=1; }
    # check in Yarn
    yarn global list --depth=0 2>&1 | grep -q "$package" && { local FOUND_IN_YARN=1; }

    if [ $FOUND_IN_YARN == 0 ] && [ $FOUND_IN_NPM == 0 ]; then
      show_message error "$package is not installed with YARN or NPM !"
      PACKAGES=( "${PACKAGES[@]/$package}" )
    fi

    if ! [[ "$PACKAGE_MANAGER" ]]; then
      if [ $FOUND_IN_YARN == 1 ]; then
        PACKAGE_MANAGER='yarn'
      elif [ $FOUND_IN_NPM == 1 ]; then
        PACKAGE_MANAGER='npm'
      fi
    fi


  done

  if [ -z "$PACKAGES" ]; then
    show_message error "No package to update!" && exit 0
  fi

  if [ "$PACKAGE_MANAGER" == "npm" ]; then
    new_line
    show_message debug "Checking $(echo "${PACKAGES[@]}") version using NPM ..."
    for package in $PACKAGES
    do
      output=$(npm -g outdated --parseable --depth=0 | grep "$package" || :)
      if [[ $output ]] ; then
        local from_version=$( echo $output | cut -d: -f3)
        local to_version=$( echo $output | cut -d: -f2)
        show_message info "[+] Updating ${package} from ${from_version} to ${to_version}... "
        _exec npm update -g $package --unsafe-perm
      else
        show_message info "[+] ${package} already installed latest version."
      fi
    done
  else
    show_message debug "Updating $(echo "${PACKAGES[@]}") using YARN ..."
    ${SUDO} yarn global upgrade-interactive moneyd codiusd --latest
  fi

  printf "\n\n"
  read -p "[?] Restarting Moneyd and Codiusd services ? [y/N]: " -e RESTART_SERVICE

  if [[ "$RESTART_SERVICE" = 'y' || "$RESTART_SERVICE" = 'Y' ]]; then
      for service in moneyd-xrp codiusd
      do
        show_message info "[-] Restarting ${service} ..."
        if [[ "${INIT_SYSTEM}" == "systemd" ]];then
          ${SUDO} systemctl restart $service
        else
          ${SUDO} service $service restart
        fi
      done
  fi
  printf "\n\n"
  show_message done "[!] Everything Done!"

  printf "\n\n"

  exit

}

################### CLEANUP ###########################

clean(){

  check_user
  check_os_platform
  check_os_distro


  show_message warn "Thie action will remove packages listed below and all config files belong to them :
  \n* Codiusd\n* Moneyd\n* Hyperd\n* Certbot\n* Nginx\n* Nodejs (npm & yarn)"

  new_line
  read -p "Continue Anyway ? [y/N]: " -e CONTINUE

  if ! [[ "$CONTINUE" = 'y' || "$CONTINUE" = 'Y' ]]; then
    exit 0
  fi

  if [[ "${LSB_DISTRO}" == "centos"  ]] || [[ "${LSB_DISTRO}" == "fedora"  ]] ;then
      ${SUDO} yum remove nodejs hyperd nginx qemu-hyper hyperstart hyper-container certbot
  elif [[ "${LSB_DISTRO}" == "ubuntu" ]] || [[ "${LSB_DISTRO}" == "debian" ]] ;then
      for i in nodejs hyperd nginx qemu-kvm libvirt0 hyperstart hypercontainer certbot aufs-tools; do ${SUDO} apt-get -y remove $i || true ;done
      ${SUDO} apt -y autoremove || true
  fi


  files_to_remove=("$HOME/.moneyd.json" "$HOME/.moneyd.json.back" "/etc/systemd/system/moneyd-xrp.service" "/etc/systemd/system/codiusd.service" , "/usr/bin/certbot")
  dirs_to_remove=("$HOME/.yarn" "/etc/letsencrypt")

  for f in "${files_to_remove[@]}"
  do
    if [[ -f $f ]]; then
      ${SUDO} rm -rf $f
    fi
  done

  for d in "${dirs_to_remove[@]}"
  do
    if [ -f "$d" ]; then 
      ${SUDO} rm -rf $d
    fi
  done


  if [[ "${INIT_SYSTEM}" == "systemd" ]];then
      ${SUDO} systemctl daemon-reload
  fi

  printf "\n\n"
  show_message done "[*] Everything cleaned successfuly!"
  printf "\n\n"

  exit 0
}


################### RENEW ###########################
renew()
{
  show_message info "[*] Checking for certificate status ..."
  new_line
  new_line


  local HOSTNAME=$(hostname)

  local canRenew=false
  local notBefore=`echo | /usr/bin/openssl s_client -connect ${HOSTNAME}:443 2>/dev/null | openssl x509 -noout -dates | grep notBefore | cut -d'=' -f2`
  local notAfter=`echo | /usr/bin/openssl s_client -connect ${HOSTNAME}:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d'=' -f2`

  local notBeforeUnix=`date --date="${notBefore}" +"%s"`
  local today=`date`
  local todayUnix=`date --date="${today}" +"%s"`
  local eightyfivedays="7344000"
  local renewDateUnix=$((notBeforeUnix + eightyfivedays))
  local renewDate=`date -d @$renewDateUnix`

  if [ $renewDateUnix -gt $todayUnix  ]; then
     show_message success "You still have time. \nToday is ${today}. \nWaiting until ${renewDate} to renew. \n${notAfter} is when your SSL cert expires. "
     new_line
     exit 0
  else
    show_message warn "Time to renew your cert. Today is ${today} and your cert expires ${notAfter}"
  fi


  #check for certbot command
  CERTBOT=$(which certbot-auto certbot|head -n1)
  if [ -z "$CERTBOT" ]; then
    show_message error "${ERR_NO_CERTBOT_INSTALLED[1]}" && exit ${ERR_NO_CERTBOT_INSTALLED[0]}
  fi

  # ask if user want's to renew
  read -p "Do you want to renew? [y/N]: " -e RENEW

  if [[ "$RENEW" = 'y' || "$RENEW" = 'Y' ]]; then
    new_line
    show_message warn "If the challenge TXT dosn't exist in your DNS please create them. \nAnd Please don't forget to wait some minute after creating records! "
    read -n1 -r -p "Press any key to continue ..."

    ${SUDO} ${CERTBOT} certonly --manual -d "${HOSTNAME}" -d "*.${HOSTNAME}" --agree-tos  --preferred-challenges dns-01  --server https://acme-v02.api.letsencrypt.org/directory

    show_message info "[!] Regenerating SSL file (it's take a while , don't panic)... "
    _exec openssl dhparam -out /etc/nginx/dhparam.pem 2048

    show_message info "[*] Restarting Nginx... "

    if [[ "${INIT_SYSTEM}" == "systemd" ]];then
      _exec "systemctl restart nginx"
    else
      _exec "service nginx restart"
    fi

    show_message done "[*] Everything done !"
    new_line
  fi

  exit 0


}


################### DEBUG ###########################
debug(){
  check_deps_initsystem

  # active debug for commands
  export DEBUG=*
  # get hostname
  local HOSTNAME=$(hostname)

  local services=( hyperd moneyd codiusd nginx )
  local commands=( node npm hyperd hyperctl moneyd codiusd certbot )
  local debug_commands=('node -v ; npm -v ; yarn -v'
    'hyperd run -t test /bin/sh'
    'hyperctl info'
    'hyperctl list'
    'moneyd xrp:start'
    'moneyd xrp:info'
    'codiusd'
    'netstat -tulpn'
  )


  new_line
  # check for codius avaiblity throught URL
  status="$(curl -Is https://${HOSTNAME}/version | head -1)"
  if [[ $status ]]; then
    validate=( $status )
    if [ ${validate[-2]} == "200" ]; then
        show_message success "[*] looks likes Codius is running property in your host ."
        new_line
        read -p "Continue Anyway ? [y/N]: " -e CONTINUE

        if ! [[ "$CONTINUE" = 'y' || "$CONTINUE" = 'Y' ]]; then
          exit 0
        fi

    else
        show_message warn "It's look like codius is not running as expected ..."
    fi
  else
     show_message warn "It's look like codius is not running as expected ..."
  fi


  show_message info "[+] Start Debuging ..."
  printf "\n\n"
  _box "Checking required installed packages"
  new_line
  echo "------------------------------------------"
  printf "%-20s %-5s\n" "PACKAGE" "STATUS"
  echo "------------------------------------------"
  for i in "${commands[@]}"
  do
    printf "%-20s %-5s" $i $(echo_if $(program_is_installed $i))
    printf "\n"
  done

  new_line
  _box "Checking required running services"
  new_line
  echo "------------------------------------------"
  printf "%-20s %-5s\n" "SERVICE" "STATUS"
  echo "------------------------------------------"
  for i in "${services[@]}"
  do
    printf "%-20s %-5s" $i $(echo_if $(service_is_running $i))
    printf "\n"
  done


  show_message info "[?] Creating full services log file ?"
  show_message warn "With this action all codius services will be restart for debuging"
  new_line
  read -p "Do you want to continue ? [y/N]: " -e DEBUG
  if ! [[ "$DEBUG" = 'y' || "$DEBUG" = 'Y' ]]; then
    exit 0
  fi


  local TMPFILE="/tmp/codius_debug-$(date +%Y-%m-%d.%H-%M)"

  show_message info "[!] Stoping services... "
  for i in "${services[@]}"
  do
    if [ "$i" = moneyd ]; then i='moneyd-xrp'; fi
    if [[ "${INIT_SYSTEM}" == "systemd" ]];then
      ${SUDO} systemctl stop $i >>"${TMPFILE}" 2>&1 
    else 
      ${SUDO} service $i stop >>"${TMPFILE}" 2>&1
    fi
 done

  show_message info "[!] Execute services and commands in debug mode ... "
  show_message info "[*] This will take some time ..."
  for c in "${debug_commands[@]}"
  do
    echo -e "\n==================================" >> "${TMPFILE}"
    echo "${c}" >> "${TMPFILE}"
    echo -e "==================================\n" >> "${TMPFILE}"
    exec 3>$(tty)
      exec 3>&-

    eval "${SUDO} bash -c '${c}'" >>"${TMPFILE}" 2>&1  &
    sleep 10
    exec 3>&-
  done

  show_message info "[!] Killing debug proccess ..."
  commands_to_kill=(moneyd codiusd hyperd)
  for p in "${commands_to_kill[@]}"
  do
    ${SUDO} kill -9 $(ps -ef|grep $p |grep -v "grep"|awk '{print $2}') || true
  done

  show_message info "[+] Starting services... "
  for i in "${services[@]}"
  do
    if [[ $i = moneyd ]]; then i='moneyd-xrp'; fi
    if [[ "${INIT_SYSTEM}" == "systemd" ]];then
      ${SUDO} systemctl restart $i >>"${TMPFILE}" 2>&1 || true
    else 
      ${SUDO} service $i restart >>"${TMPFILE}" 2>&1 || true
    fi
  done

  new_line
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =
  show_message done "[!] The Debuging Proccess is done ."
  new_line
  show_message done "[-] Please check $TMPFILE for full log output ."
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =


  exit

}


################### CHECK FOR SCRIPT UPDATES ###########################

check_script_update() {
  INSTALLER_URL="https://raw.githubusercontent.com/xrp-community/codius-install/master/codius-install.sh"
  LATEST_FILE=$(curl "$INSTALLER_URL" 2>/dev/null) || { printf '%s\n' 'Unable to check for updates.'; curlFailed=1; }
  THIS_MOD=$(grep -m1 '# Last Modified Date: ' $0)
  LASTED_MOD=$(grep -m1 '# Last Modified Date: ' <<<"$LATEST_FILE")

  if [[ "$THIS_MOD" != "$LASTED_MOD" ]] &&  [[ ! -n "$curlFailed" ]]; then
    show_message info "[!] An update is available For the script... "
    read -p "Update Now ? [y/N]: " -e UPDATE

    if [[ "$UPDATE" = 'y' || "$UPDATE" = 'Y' ]]; then
      show_message info "[+] Updating now.\n"
      tmpfile=$(mktemp)
      chmod +x "$tmpfile"
      cat <<<"$LATEST_FILE" > "$tmpfile"
      mv "$tmpfile" "$0"
      show_message done "\n[-] Installer successfuly updated to the latest version , please restart the script to continue.\n"
      exit
    fi
  fi

  new_line

}

################### MAIN ###########################

while :
do
  clear
  display_header

  # check for script Update at startup
  check_script_update

  echo "What do you want to do?"
                  echo "   1) Install and run Codius in your system"
                  echo "   2) Check your system for codius errors"
                  echo "   3) Check for certificate status and renew"
                  echo "   4) Cleanup the codius from the server"
                  echo "   5) Update Moneyd & Codius to the lastest version"
                  echo "   6) Exit"
  read -p "Select an option [1-6]: " option

  case $option in
    1)install;;
    2)debug;;
    3)renew;;
    4)clean;;
    5)update;;
    6)exit;;
  esac
done

