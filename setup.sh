#!/usr/bin/env bash
############################################################
# usage:
#     setup.sh
############################################################

set -e # exit when any command fails

# banner
echo -e "$(
cat <<EOF
\e[37m##################################################################################\e[0m
\e[37m#\e[0m                                                                                \e[37m#\e[0m
\e[37m#\e[0m  \e[34m  ooooooo   ooooo  oooo ooooo ooooo\e[0m      \e[94mooooo  oooo oooooooooo   oooooooo8   \e[37m#\e[0m
\e[37m#\e[0m  \e[34mo888   888o  888    88   888   888 \e[0m      \e[94m 888    88   888    888 888          \e[37m#\e[0m
\e[37m#\e[0m  \e[34m888     888   888  88    888ooo888 \e[0m      \e[94m  888  88    888oooo88   888oooooo   \e[37m#\e[0m
\e[37m#\e[0m  \e[34m888o   o888    88888     888   888 \e[0m      \e[94m   88888     888                888  \e[37m#\e[0m
\e[37m#\e[0m  \e[34m  88ooo88       888     o888o o888o\e[0m      \e[94m    888     o888o       o88oooo888   \e[37m#\e[0m
\e[37m#\e[0m             \e[95m  ______     ______     ______   __  __     ______                 \e[37m#\e[0m
\e[37m#\e[0m             \e[95m /\  ___\   /\  ___\   /\__  _\ /\ \/\ \   /\  == \                \e[37m#\e[0m
\e[37m#\e[0m             \e[95m \ \___  \  \ \  __\   \/_/\ \/ \ \ \_\ \  \ \  _-/                \e[37m#\e[0m
\e[37m#\e[0m             \e[95m  \/\_____\  \ \_____\    \ \_\  \ \_____\  \ \_\                  \e[37m#\e[0m
\e[37m#\e[0m             \e[95m   \/_____/   \/_____/     \/_/   \/_____/   \/_/                  \e[37m#\e[0m
\e[37m#\e[0m                                                                                \e[37m#\e[0m
\e[37m##################################################################################\e[0m
EOF
)"


############################################################
# utility functions
############################################################
function print_info {
  echo -n -e '\e[1;36m'
  echo -n $1
  echo -e '\e[0m'
}

function print_warn {
  echo -n -e '\e[1;33m'
  echo -n $1
  echo -e '\e[0m'
}

function die {
  echo -n -e '\e[1;31m' > /dev/null 1>&2
  echo "ERROR: $1" > /dev/null 1>&2
  echo -e '\e[0m' > /dev/null 1>&2
  exit 1
}

function ask {
  local prompt default reply
  if [[ ${2:-} = 'Y' ]]; then
      prompt='Y/n'
      default='Y'
  elif [[ ${2:-} = 'N' ]]; then
      prompt='y/N'
      default='N'
  else
      prompt='y/n'
      default=''
  fi

  while true; do
      echo -ne "\e[32m$1 [$prompt] \e[0m"
      read -r reply </dev/tty
      if [[ -z $reply ]]; then
          reply=$default
      fi
      case "$reply" in
          Y*|y*) return 0 ;;
          N*|n*) return 1 ;;
      esac
  done
}

function input {
  local prompt default
  input_reply=""
  if [[ -n $2 ]]; then
    default="$2"
    prompt=" [$2]"
  fi
  while true; do
      echo -ne "\e[33m$1$prompt: \e[0m"
      # secure input for password
      if [[ -n $3 ]]; then
        read -rs input_reply </dev/tty
        echo ""
      else
        read -r input_reply </dev/tty
      fi
      if [[ -z $input_reply ]]; then
          input_reply=$default
      fi
      if [[ -n $input_reply ]];then
        return
      fi
  done

}
############################################################

# function to restore the SSH configuration
function restore_ssh_configs {
  if [ -f sshd.bak -a -f sshd_config.bak ]; then
    sudo cp sshd.bak /etc/pam.d/sshd
    sudo cp sshd_config.bak /etc/ssh/sshd_config
    sudo rm sshd.bak
    sudo rm sshd_config.bak
    print_warn "SSH backup configuration restored!"
  fi
}

# function to setup SSH key authentication
function setup_ssk_key {
  print_info "Generate a SSH key pair on client side with 'ssh-keygen'"
  input "Copy-paste the client public key (id_rsa.pub) just here"
  mkdir -p ~/.ssh
  echo "${input_reply}" >> ~/.ssh/authorized_keys
  chmod -R go= ~/.ssh
  print_info "==> Open another SSH session to test the SSH Key authentication"
  print_warn "==> But do not close this SSH session!!!"
  if ! ask "Is the authentication via SSH key working correctly?";then
    restore_ssh_config
    sed -i "/$input_reply/d" ~/.ssh/authorized_keys
    die "SSH key authentication doesn't work, abort this program"
  fi
}

# function to update and install software
function install {
  if [ "$apt_update_done" = false ]; then
    sudo apt update
    apt_update_done=true
 fi
 sudo apt -y install "$@"
}

# function wrapper to iptables/ip6tables
function xtables {
  if [ "$ipv6_enable" = true ]; then
    sudo ip6tables "$@"
  fi
  sudo iptables "$@"
}

############################################################
# main
############################################################

# globals
ssh_2fa_enable=false
apt_update_done=false
email_alert_enable=false
ipv6_enable=false

# check the OS distribution
if [ ! -f /etc/os-release ]; then
    die "This script only support Ubuntu 20.04"
else
  . /etc/os-release
  if [ "${ID}" != "ubuntu" -a "${VERSION_ID}" != "20.04" ]; then
    die "This script only support Ubuntu 20.04"
  fi
fi

# Software update
if ask "Do you want to update and upgrade the OS software?" Y;then
  print_info "apt update"
  sudo apt -y update
  apt_update_done=true
  print_info "apt upgrade"
  sudo apt -y upgrade
fi

# Change user password
if ask "Do you want to change the current user password?" Y;then
  passwd
fi

# Create a new user
if ask "Do you want to create a new user on this server?" N;then
  input "Please enter the new user name"
  sudo adduser --gecos "" "$input_reply"
  sudo usermod -aG sudo "$input_reply"
  if ask "Reply 'Y' if you want to continue the configuration for the new user (this script will exit)?" Y;then
    print_warn "Please re-open a SSH session with the newly created user and execute this script again."
    exit 0
  fi
fi

# Delete an user
if ask "Do you want to delete other user(s) on this server?" N;then
  echo "$(eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)} | cut -d: -f1 | grep -v $USER)"
  input "Please enter the user you want to delete from the list above (the home folder will be deleted)"
  sudo deluser --remove-home "$input_reply"
  while ask "Do you want to delete another user?";do
    input "Please type the user you want to delete (home folder will be deleted)"
    sudo deluser --remove-home "$input_reply"
  done
fi

# Git configuration
if ask "Do you want to install and configure Git?" Y;then
  print_info "Git setup"
  install git
  cp gitconfig ~/.gitconfig
  input "Enter your Git username" "John Doe"
  git config --global user.name "${input_reply}"
  input "Enter your Git email" "john.doe@mail.com"
  git config --global user.email "${input_reply}"
  git config --global credential.username "${input_reply}"
fi

# Set the hostname and FQDN
if ask "Do you want to change the current server hostname and FQDN (DNS)?" Y;then
  input "Enter the new hostname"
  new_hostname="$input_reply"
  sudo hostnamectl set-hostname "$new_hostname"
  input "Enter your server FQDN" "exemple.org"
  sudo sed -i "s|^127\.0\.1\.1.*$|127\.0\.1\.1 $new_hostname\.$input_reply $new_hostname|g" /etc/hosts
  print_info "hostname:"
  hostname
  print_info "FQDN:"
  hostname -f
  print_info "DNS domain name:"
  dnsdomainname
  input "Please review the information above and press enter when done" " "
fi

# Set the timezone
if ask "Do you want to configure this server local timezone?" Y;then
  print_info "Select your timezone from the list below:"
  tz=$(tzselect|tail -1)
  sudo timedatectl set-timezone "$tz"
fi

# Enable IPv6
if ask "Do you want to enable and configure the IPv6 network?" Y;then
  print_info "Configure the static IPv6 network"
  public_iface=$(ip route show default | awk '/default/ {print $5}')
  input "Enter the default route interface" "${public_iface}"
  sed -i "s|%PUBLIC_IFACE|$input_reply|g" 51-cloud-init-ipv6.yaml
  input "Enter the IPv6 address"
  sed -i "s|%IPv6_ADDRESS|$input_reply|g" 51-cloud-init-ipv6.yaml
  input "Enter the IPv6 address prefix" "128"
  sed -i "s|%IPv6_PREFIX|$input_reply|g" 51-cloud-init-ipv6.yaml
  input "Enter the IPv6 gateway"
  sed -i "s|%IPv6_GATEWAY|$input_reply|g" 51-cloud-init-ipv6.yaml
  sudo cp 51-cloud-init-ipv6.yaml /etc/netplan
  sudo netplan try
  sudo netplan apply
  ipv6_enable=true
fi

# Enable SSH 2FA
if ask "Do you want to enable SSH 2FA?" Y;then
  print_info "Install google-authenticator"
  install libpam-google-authenticator
  # google-authenticator settings
  # -t => Time based counter
  # -d => Disallow token reuse
  # -f => Force writing the settings to file without prompting the user
  # -r => How many attempts to enter the correct code
  # -R => How long in seconds a user can attempt to enter the correct code
  # -w => How many codes can are valid at a time (this references the 1:30 min - 4 min window of valid codes)
  google-authenticator -t -d -f -r 3 -R 30 -w 3
  if [ ! -f sshd.bak ]; then
    sudo cp /etc/pam.d/sshd sshd.bak
  fi
  echo "auth required pam_google_authenticator.so nullok" | sudo tee -a /etc/pam.d/sshd > /dev/null
  echo "auth required pam_permit.so" | sudo tee -a /etc/pam.d/sshd > /dev/null
  if [ ! -f sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config sshd_config.bak
  fi
  sudo sed -i "s|^ChallengeResponseAuthentication.*$|ChallengeResponseAuthentication yes|g" /etc/ssh/sshd_config
  sudo systemctl restart sshd.service
  print_info "Please save the TOTP information above in 'Google Authenticator' alike app"
  print_info "==> Open another SSH session to test the 2FA authentication"
  print_warn "==> But do not close this SSH session!!!"
  if ! ask "Is the 2FA authentication working correctly?";then
    restore_ssh_config
    die "SSH 2FA doesn't work, abort this program"
  fi
  ssh_2fa_enable=true
fi

# Setup SSH Keys
if ask "Do you want to enable authentication via SSH keys?" Y;then
  if [ "$ssh_2fa_enable" = true ]; then
    # update ssh config to support SSH key + 2FA authentication
    if [ ! -f sshd.bak ]; then
      sudo cp /etc/pam.d/sshd sshd.bak
    fi
    sudo sed -i "s|^@include common-auth$|#@include common-auth|g" /etc/pam.d/sshd
    if [ ! -f sshd_config.bak ]; then
      sudo cp /etc/ssh/sshd_config sshd_config.bak
    fi
    echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    sudo systemctl restart sshd.service
  fi
  setup_ssk_key
  while ask "Do you want to add another SSH key client?";do
    setup_ssk_key
  done
fi

# Setup fail2ban for SSH
if ask "Do you want to install fail2ban to protect SSH?" Y;then
  install fail2ban
  sudo systemctl enable fail2ban
  sudo systemctl start fail2ban
  sudo fail2ban-client status sshd
fi

# Setup email alerts
if ask "Do you want to receive email alerts from this server (only support Gmail SMTP server)?" Y;then
  input "Please enter the email addressses to receive the alerts (comma separated list)"
  sudo sed -i "/^EMAIL_RECIPIENTS=.*/d" /etc/environment
  email_recipients="${input_reply}"
  echo "EMAIL_RECIPIENTS=${email_recipients}" | sudo tee -a /etc/environment > /dev/null
  email_alert_enable=true
  echo postfix postfix/main_mailer_type string Internet Site | sudo debconf-set-selections
  echo postfix postfix/mailname string $HOSTNAME | sudo debconf-set-selections
  print_info "Install postfix"
  install postfix
  print_info "Configure postfix"
  sudo sed -i '/^relayhost =.*/,$d' /etc/postfix/main.cf
  postfix_conf=$(cat <<EOF
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/postfix/cacert.pem
smtp_use_tls = yes
EOF
)
  echo "$postfix_conf" | sudo tee -a /etc/postfix/main.cf > /dev/null
  input "Please enter your Gmail email" "john.doe@gmail.com"
  gmail_email="$input_reply"
  print_warn "To create a Gmail appication password check this link: https://devanswers.co/create-application-specific-password-gmail/"
  input "Please enter your generated app password (hidden)" "" "password"
  gmail_password="$input_reply"
  echo "[smtp.gmail.com]:587 ${gmail_email}:${gmail_password}" | sudo tee /etc/postfix/sasl_passwd > /dev/null
  sudo postmap /etc/postfix/sasl_passwd
  sudo chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
  sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
  print_info "Sign certificate"
  cat /etc/ssl/certs/GlobalSign_Root_CA_-_R2.pem | sudo tee -a /etc/postfix/cacert.pem > /dev/null
  if ask "Do you want to send a test email to '${gmail_email}'?" Y;then
    echo "This is a test email."  | mail -s "[$HOSTNAME] Email Test" ${gmail_email}
    print_info "email sent!"
  fi
fi

# Setup SSH login alerts
if ask "Do you want to receive email alerts on SSH login?" Y;then
  print_info "Setup SSH login alert"
  sudo mkdir -p /etc/pam.scripts
  sudo chmod 0755 /etc/pam.scripts
  sudo cp ssh_email_alert.sh /etc/pam.scripts
  sudo chmod 0700 /etc/pam.scripts/ssh_email_alert.sh
  sudo chown root:root /etc/pam.scripts/ssh_email_alert.sh
  echo "session required pam_exec.so /etc/pam.scripts/ssh_email_alert.sh" | sudo tee -a /etc/pam.d/sshd > /dev/null
  print_info "Open another SSH session if you want to test the SSH login email alert"
  input "When done, press 'Enter' to continue" " "
fi

# Setup alert on reboot
if ask "Do you want to receive email alert on reboot?" Y;then
  print_info "Setup reboot email alert"
  (sudo crontab -l 2>/dev/null; echo "@reboot echo \"Please check your server if the reboot was not expected.\" | mail -s \"[\$(hostname)] System was rebooted on \$(date)\" \$EMAIL_RECIPIENTS") | sudo crontab -u root -
fi

# Setup PSAD
if ask "Do you want to install PSAD (Port Scan Attack Detection)?" Y;then
  if [ "$email_alert_enable" = false ]; then
    echo postfix postfix/main_mailer_type string Local only | sudo debconf-set-selections
    echo postfix postfix/mailname string $HOSTNAME | sudo debconf-set-selections
  fi
  print_info "Install PSAD"
  install psad
  print_info "Configure PSAD"
  if [ "$email_alert_enable" = true ]; then
    sudo sed -i "s|^EMAIL_ADDRESSES .*|EMAIL_ADDRESSES $email_recipients;|g" /etc/psad/psad.conf
    # Set danger Level to 5
    sudo sed -i "s|^EMAIL_ALERT_DANGER_LEVEL .*|EMAIL_ALERT_DANGER_LEVEL 5;|g" /etc/psad/psad.conf
  fi
  sudo sed -i "s|^HOSTNAME .*|HOSTNAME $HOSTNAME;|g" /etc/psad/psad.conf
  sudo sed -i "s|^IPT_SYSLOG_FILE .*|IPT_SYSLOG_FILE /var/log/syslog;|g" /etc/psad/psad.conf
  sudo sed -i "s|^ENABLE_AUTO_IDS .*|ENABLE_AUTO_IDS Y;|g" /etc/psad/psad.conf
  # ignore these IPs
  echo "127.0.0.0/8 0;" | sudo tee -a /etc/psad/auto_dl > /dev/null
  echo "::1 0;" | sudo tee -a /etc/psad/auto_dl > /dev/null
  print_info "Update PSAD signatures"
  sudo systemctl enable psad
  sudo psad --sig-update
  sudo systemctl restart psad
  print_info "PSAD status"
  sudo psad -S
fi

# Setup IPv4/IPv6 Firewall
network_type="IPv4"
[ "$ipv6_enable" = true ] && network_type="IPv4 & IPv6"
if ask "Do you want to setup the $network_type firewall?" Y;then
  # reset the firewall
  xtables -P INPUT ACCEPT
  xtables -P FORWARD ACCEPT
  xtables -P OUTPUT ACCEPT
  xtables -F INPUT
  xtables -F FORWARD
  xtables -F OUTPUT
  xtables -t nat -F

  # make firewall changes persistent
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
  print_info "Create iptables persitant rules"

  xtables -A INPUT -i lo -j ACCEPT
  xtables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  xtables -A INPUT -p tcp --dport 22 -j ACCEPT
  [ "$ipv6_enable" = true ] && sudo ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp -j ACCEPT

  # Accept ping requests
  if ask "Do you want to accept incoming 'ping' requests?" Y;then
    sudo iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
    [ "$ipv6_enable" = true ] && sudo ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j ACCEPT
  fi

  # Set Random TCP port for SSH server
  if ask "Do you want to use a random TCP port for SSH server?" Y;then
    random_port=$(shuf -i 49152-65535 -n 1)
    input "Press enter or choose another TCP port for SSH" "$random_port"
    new_port="$input_reply"
    public_iface=$(ip route show default | awk '/default/ {print $5}')
    wan_ipv4=$(ip -o a s $public_iface | grep global | awk '{print $4;exit}')
    sudo iptables -t nat -I PREROUTING -d "$wan_ipv4" -i "$public_iface" -p tcp -m tcp --dport 22 -j REDIRECT --to-port 65535
    sudo iptables -t nat -A PREROUTING -d "$wan_ipv4" -i "$public_iface" -p tcp -m tcp --dport "$new_port" -j REDIRECT --to-ports 22
    if [ "$ipv6_enable" = true ]; then
      wan_ipv6=$(ip -o -6 a s $public_iface | grep global | awk '{print $4;exit}')
      sudo ip6tables -t nat -I PREROUTING -d "$wan_ipv6" -i "$public_iface" -p tcp -m tcp --dport 22 -j REDIRECT --to-port 65535
      sudo ip6tables -t nat -A PREROUTING -d "$wan_ipv6" -i "$public_iface" -p tcp -m tcp --dport "$new_port" -j REDIRECT --to-ports 22
    fi
    print_warn "You can try to open another SSH session with the port: $new_port"
    input "Press enter to continue" " "
  fi

  xtables -A INPUT -j LOG
  xtables -A FORWARD -j LOG
  xtables -P INPUT DROP
  xtables -P FORWARD DROP

  print_info "Install iptables-persistent"
  install iptables-persistent
  sudo systemctl enable netfilter-persistent
  sudo netfilter-persistent save
fi
