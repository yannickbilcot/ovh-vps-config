#!/usr/bin/env bash
############################################################
# usage:
#     setup.sh [-a <setup.cfg>]
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
  echo -n "$1"
  echo -e '\e[0m'
}

function print_warn {
  echo -n -e '\e[1;33m'
  echo -n "$1"
  echo -e '\e[0m'
}

function die {
  echo -n -e '\e[1;31m' > /dev/null 1>&2
  echo "ERROR: $1" > /dev/null 1>&2
  echo -e '\e[0m' > /dev/null 1>&2
  exit 1
}

function ask {
  local prompt default reply cfg

  if [[ "$non_interactive_mode" = true ]]; then
    cfg="${!#}"
    if [ "${!cfg}" = true ]; then
      echo -ne "\e[32m$1 \e[1;35mYes\e[0m\n"
      return 0
    fi
    if [ "${!cfg}" = false ]; then
      echo -ne "\e[32m$1 \e[1;35mNo\e[0m\n"
      return 1
    fi
    arg="$#"
    die "non-interactive mode: \"$1\" [${!arg}]"
  fi

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
  local prompt default cfg
  input_reply=""

  if [[ "$non_interactive_mode" = true ]]; then
    cfg="${!#}"
    if [ -n "${!cfg}" ]; then
      if [[ "$3" = "password" ]]; then
        echo -ne "\e[33m$1: \e[1;35m********\e[0m\n"
      else
        echo -ne "\e[33m$1: \e[1;35m${!cfg}\e[0m\n"
      fi
      input_reply="${!cfg}"
      return
    fi
    arg="$#"
    die "non-interactive mode: \"$1\" [${!arg}]"
  fi

  if [[ -n $2 ]]; then
    default="$2"
    prompt=" [$2]"
  fi
  while true; do
      echo -ne "\e[33m$1$prompt: \e[0m"
      # secure input for password
      if [[ "$3" = "password" ]]; then
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

# function to get the latest Github release tag from repo
function get_github_latest_release {
  curl --silent "https://api.github.com/repos/$1/releases/latest" |
    grep '"tag_name":' |
    sed -E 's/.*"([^"]+)".*/\1/'
}

# function to restore the SSH configuration
function restore_ssh_configs {
  if [ -f "$DIR"/sshd.bak ] && [ -f "$DIR"/sshd_config.bak ]; then
    sudo cp "$DIR"/sshd.bak /etc/pam.d/sshd
    sudo cp "$DIR"/sshd_config.bak /etc/ssh/sshd_config
    sudo rm "$DIR"/sshd.bak
    sudo rm "$DIR"/sshd_config.bak
    print_warn "SSH backup configuration restored!"
  fi
}

# function to setup SSH key authentication
function setup_ssk_key {
  mkdir -p ~/.ssh
  if [ "$non_interactive_mode" = true ]; then
    for key in "${CFG_ssh_public_keys_list[@]:?}"; do
      print_info "Add SSH public key:"
      echo "$key"
      echo "$key" >> ~/.ssh/authorized_keys
    done
    return
  fi
  print_info "Generate a SSH key pair on client side with 'ssh-keygen'"
  input "Copy-paste the client public key just here"
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

# function to generate wireguard client config
function wg_create_client {
  local network_mode="$1"
  local id="$2"
  local address=""
  local allowed_ips=""

  print_info "Generate config for the client #$id [$network_mode]"
  client_private_key=$(wg genkey)
  client_public_key=$(echo "${client_private_key}" | wg pubkey)

  if [ "$network_mode" = "ip4" ]; then
    address="${wg_server_ipv4::-1}$((id+1))/32"
  elif [ "$network_mode" = "ip6" ]; then
    address="${wg_server_ipv6::-1}$((id+1))/128"
  elif [ "$network_mode" = "dual" ]; then
    address="${wg_server_ipv4::-1}$((id+1))/32, ${wg_server_ipv6::-1}$((id+1))/128"
  else
    die "Wireguard create client issue: mode should be [ip4|ip6|dual]"
  fi

  if [ "$wg_ipv4_enable" = true ] && [ "$wg_ipv6_enable" = true ]; then
    allowed_ips="0.0.0.0/0, ::/0"
  elif [ "$wg_ipv4_enable" = false ]; then
    allowed_ips="::/0"
  else
    allowed_ips="0.0.0.0/0"
  fi

  cat > "$DIR/wg-client$id.conf" <<EOL
[Interface]
PrivateKey = ${client_private_key}
Address = ${address}

[Peer]
PublicKey = ${server_public_key}
AllowedIPs = ${allowed_ips}
Endpoint = $(hostname -f):${wg_server_port}
PersistentKeepalive = 25
EOL

  cat >> "$DIR/${wg_server_cfg}" <<EOL

[Peer]
PublicKey = ${client_public_key}
AllowedIPs = ${address}
EOL
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

# function to parse the config file
function parse_config {
  print_info "Parse config file: $1"
  eval "$(awk -F= '!/^#/ && !/^$/ && /^[a-zA-Z_]{1,}[a-zA-Z0-9_]{0,}=.*/ { gsub("\\\\","\\\\",$2); gsub("\\$","\\\$",$2); gsub("`","\\`",$2); printf("CFG_%s=%s\n",$1,$2);}' "$1" 2> /dev/null)"
}

############################################################
# main
############################################################

# globals
ssh_2fa_enable=false
apt_update_done=false
email_alert_enable=false
ipv6_enable=false
non_interactive_mode=false
docker_compose_systemd_unit=false
config_file="setup.cfg"
public_iface=$(ip route show default | awk '/default/ {print $5}')

# wireguard globals
wg_enable=false
wg_server_ipv4="10.0.0.1"
wg_server_ipv6="fd01:8bad:f00d:1::1"
wg_server_cfg="wg0.conf"

# Repository directory
DIR=$(echo "$0" | rev | cut -d'/' -f 2- | rev)

# check the OS distribution
if [ ! -f /etc/os-release ]; then
    die "This script only supports Ubuntu 20.04"
else
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID}" != "ubuntu" ] && [ "${VERSION_ID}" != "20.04" ]; then
    die "This script only supports Ubuntu 20.04"
  fi
fi

# Chech input for non-interactive mode
if [ "$1" = "-a" ] ; then
  non_interactive_mode=true
  if [ -n "$2" ]; then
    parse_config "$2"
  else
    parse_config "${DIR}/${config_file}"
  fi
fi

# Software update
if ask "Update and upgrade the OS software?" Y "CFG_update_and_upgrade";then
  print_info "apt update"
  sudo apt -y update
  apt_update_done=true
  print_info "apt upgrade"
  sudo apt -y upgrade
fi

# Change user password
if ask "Change the current user password?" Y "CFG_change_user_password";then
  if [ "$non_interactive_mode" = true ]; then
    input "User new password" "" "password" "CFG_user_new_password"
    echo -e "$input_reply\n$input_reply" | sudo passwd "$USER"
  else
    passwd
  fi
fi

# Create a new user
if ask "Create a new user on this server?" N "CFG_create_new_user";then
  if [ "$non_interactive_mode" = true ]; then
    i=0
    for user in "${CFG_user_name_list[@]:?}"; do
      print_info "Create new user: $user"
      sudo adduser --gecos "" --disabled-password "$user"
      echo -e "${CFG_user_password_list[$i]:?}\n${CFG_user_password_list[$i]:?}" | sudo passwd "$user"
      i=$((i+1))
    done
  else
    input "Please enter the new user name"
    sudo adduser --gecos "" "$input_reply"
    sudo usermod -aG sudo "$input_reply"
    if ask "Reply 'Y' if you want to continue the configuration for the new user (this script will exit)?" Y;then
      print_warn "Please re-open a SSH session with the newly created user and execute this script again."
      exit 0
    fi
  fi
fi

# Delete an user
if ask "Delete other user(s) on this server?" N "CFG_delete_users";then
  if [ "$non_interactive_mode" = true ]; then
    for user in "${CFG_delete_users_list[@]:?}"; do
      print_info "Delete user: $user"
      sudo deluser --remove-home "$user"
    done
  else
    eval getent passwd "{$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)}" | cut -d: -f1 | grep -v "$USER"
    input "Please enter the user you want to delete from the list above (the home folder will be deleted)"
    sudo deluser --remove-home "$input_reply"
    while ask "Delete another user?";do
      input "Please type the user you want to delete (home folder will be deleted)"
      sudo deluser --remove-home "$input_reply"
    done
  fi
fi

# Set the hostname and FQDN
if ask "Change the current server hostname and FQDN (DNS)?" Y "CFG_set_hostname_and_fqdn";then
  input "Enter the new hostname" "" "CFG_server_hostname"
  new_hostname="$input_reply"
  sudo hostnamectl set-hostname "$new_hostname"
  input "Enter your server FQDN" "example.org" "CFG_server_fqdn"
  sudo sed -i "s|^127\.0\.1\.1.*$|127\.0\.1\.1 $new_hostname\.$input_reply $new_hostname|g" /etc/hosts
  print_info "hostname:"
  hostname
  print_info "FQDN:"
  hostname -f
  print_info "DNS domain name:"
  dnsdomainname
fi

# Set the timezone
if ask "Configure this server local timezone?" Y "CFG_set_timezone";then
  if [ "$non_interactive_mode" = false ]; then
    print_info "Select your timezone from the list below:"
    tz=$(tzselect|tail -1)
  else
    input "Enter the local timezone" "" "CFG_tz"
    tz="$input_reply"
  fi
  sudo timedatectl set-timezone "$tz"
  timedatectl show
fi

# Enable IPv6
if ask "Enable and configure the IPv6 network?" Y "CFG_enable_ipv6";then
  print_info "Configure the static IPv6 network"
  sed -i "s|%PUBLIC_IFACE|$public_iface|g" "$DIR"/51-cloud-init-ipv6.yaml
  input "Enter the IPv6 address" "" "CFG_ipv6_address"
  sed -i "s|%IPv6_ADDRESS|$input_reply|g" "$DIR"/51-cloud-init-ipv6.yaml
  input "Enter the IPv6 address prefix" "128" "CFG_ipv6_prefix"
  sed -i "s|%IPv6_PREFIX|$input_reply|g" "$DIR"/51-cloud-init-ipv6.yaml
  input "Enter the IPv6 gateway" "" "CFG_ipv6_gateway"
  sed -i "s|%IPv6_GATEWAY|$input_reply|g" "$DIR"/51-cloud-init-ipv6.yaml
  sudo cp "$DIR"/51-cloud-init-ipv6.yaml /etc/netplan
  sudo netplan try
  sudo netplan apply
  ipv6_enable=true
fi

# Enable SSH 2FA
if ask "Enable SSH 2FA?" Y "CFG_enable_ssh_2fa";then
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
  if [ ! -f "$DIR"/sshd.bak ]; then
    sudo cp /etc/pam.d/sshd "$DIR"/sshd.bak
  fi
  echo "auth required pam_google_authenticator.so nullok" | sudo tee -a /etc/pam.d/sshd > /dev/null
  echo "auth required pam_permit.so" | sudo tee -a /etc/pam.d/sshd > /dev/null
  if [ ! -f "$DIR"/sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config "$DIR"/sshd_config.bak
  fi
  sudo sed -i "s|^ChallengeResponseAuthentication.*$|ChallengeResponseAuthentication yes|g" /etc/ssh/sshd_config
  sudo systemctl restart sshd.service
  print_info "Please save the TOTP information above in 'Google Authenticator' alike app"
  if [ "$non_interactive_mode" = false ]; then
    print_info "==> Open another SSH session to test the 2FA authentication"
    print_warn "==> But do not close this SSH session!!!"
    if ! ask "Is the 2FA authentication working correctly?";then
      restore_ssh_config
      die "SSH 2FA doesn't work, abort this program"
    fi
  fi
  ssh_2fa_enable=true
fi

# Setup SSH Keys
if ask "Enable authentication via SSH keys?" Y "CFG_enable_ssh_keys";then
  if [ "$ssh_2fa_enable" = true ]; then
    # update ssh config to support SSH key + 2FA authentication
    if [ ! -f "$DIR"/sshd.bak ]; then
      sudo cp /etc/pam.d/sshd "$DIR"/sshd.bak
    fi
    sudo sed -i "s|^@include common-auth$|#@include common-auth|g" /etc/pam.d/sshd
    if [ ! -f "$DIR"/sshd_config.bak ]; then
      sudo cp /etc/ssh/sshd_config "$DIR"/sshd_config.bak
    fi
    echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    sudo systemctl restart sshd.service
  fi
  setup_ssk_key
  if [ "$non_interactive_mode" = false ]; then
    while ask "Add another SSH key client?";do
      setup_ssk_key
    done
  fi
fi

# Setup fail2ban for SSH
if ask "Install fail2ban to protect SSH?" Y "CFG_install_fail2ban";then
  install fail2ban
  sudo systemctl enable fail2ban
  sudo systemctl start fail2ban
  sudo fail2ban-client status sshd
fi

# Setup email alerts
if ask "Receive email alerts from this server (only support Gmail SMTP server)?" Y "CFG_enable_email_alerts";then
  input "Please enter the email addressses to receive the alerts (comma separated list)" "" "CFG_email_recipients"
  sudo sed -i "/^EMAIL_RECIPIENTS=.*/d" /etc/environment
  email_list="${input_reply}"
  echo "EMAIL_RECIPIENTS=${email_list}" | sudo tee -a /etc/environment > /dev/null
  email_alert_enable=true
  echo postfix postfix/main_mailer_type string Internet Site | sudo debconf-set-selections
  echo postfix postfix/mailname string "$HOSTNAME" | sudo debconf-set-selections
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
  input "Please enter your Gmail email" "john.doe@gmail.com" "CFG_gmail_address"
  gmail_email="$input_reply"
  print_warn "To create a Gmail appication password check this link: https://support.google.com/mail/answer/185833?hl=en"
  input "Please enter your generated app password (hidden)" "" "password" "CFG_gmail_app_password"
  gmail_password="$input_reply"
  echo "[smtp.gmail.com]:587 ${gmail_email}:${gmail_password}" | sudo tee /etc/postfix/sasl_passwd > /dev/null
  sudo postmap /etc/postfix/sasl_passwd
  sudo chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
  sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
  print_info "Sign certificate"
  # shellcheck disable=SC2002
  cat /etc/ssl/certs/GlobalSign_Root_CA_-_R2.pem | sudo tee -a /etc/postfix/cacert.pem > /dev/null
  if ask "Send a test email to '${gmail_email}'?" Y "CFG_send_test_email";then
    echo "This is a test email."  | mail -s "[$HOSTNAME] Email Test" "${gmail_email}"
    print_info "email sent!"
  fi

  # Alert on SSH login
  if ask "Receive email alerts on SSH login?" Y "CFG_ssh_login_alert";then
    print_info "Setup SSH login alert"
    sudo mkdir -p /etc/pam.scripts
    sudo chmod 0755 /etc/pam.scripts
    sudo cp "$DIR"/ssh_email_alert.sh /etc/pam.scripts
    sudo chmod 0700 /etc/pam.scripts/ssh_email_alert.sh
    sudo chown root:root /etc/pam.scripts/ssh_email_alert.sh
    echo "session required pam_exec.so /etc/pam.scripts/ssh_email_alert.sh" | sudo tee -a /etc/pam.d/sshd > /dev/null
    if [ "$non_interactive_mode" = false ]; then
      print_info "Open another SSH session if you want to test the SSH login email alert"
      input "When done, press 'Enter' to continue" " "
    fi
  fi

  # Alert on reboot
  if ask "Receive email alert on reboot?" Y "CFG_reboot_alert";then
    print_info "Setup reboot email alert"
    (sudo crontab -l 2>/dev/null; echo "@reboot echo \"Please check your server if the reboot was not expected.\" | mail -s \"[\$(hostname)] System was rebooted on \$(date)\" \$EMAIL_RECIPIENTS") | sudo crontab -u root -
  fi

  # Alert on security unattended upgrade
  if ask "Receive email alert on system security unattended upgrade?" Y "CFG_unattended_upgrade_alert";then
    print_info "Setup unattended upgrade email alert"
    sudo sed -i "s|^//Unattended-Upgrade::Mail .*|Unattended-Upgrade::Mail \"$EMAIL_RECIPIENTS\";|g" /etc/apt/apt.conf.d/50unattended-upgrades
    sudo sed -i "s|^//Unattended-Upgrade::MailReport .*|Unattended-Upgrade::MailReport \"on-change\";|g" /etc/apt/apt.conf.d/50unattended-upgrades
  fi
fi

# Setup PSAD
if ask "Install PSAD (Port Scan Attack Detection)?" Y "CFG_install_psad";then
  if [ "$email_alert_enable" = false ]; then
    echo postfix postfix/main_mailer_type string Local only | sudo debconf-set-selections
    echo postfix postfix/mailname string "$HOSTNAME" | sudo debconf-set-selections
  fi
  print_info "Install PSAD"
  install psad
  print_info "Configure PSAD"
  if [ "$email_alert_enable" = true ]; then
    sudo sed -i "s|^EMAIL_ADDRESSES .*|EMAIL_ADDRESSES $email_list;|g" /etc/psad/psad.conf
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
if ask "Setup the $network_type firewall?" Y "CFG_firewall_setup";then
  # reset the firewall
  xtables -P INPUT ACCEPT
  xtables -P FORWARD ACCEPT
  xtables -P OUTPUT ACCEPT
  xtables -t nat -F
  xtables -t mangle -F
  xtables -F
  xtables -X

  # make firewall changes persistent
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
  print_info "Create iptables persitant rules"

  xtables -A INPUT -i lo -j ACCEPT
  xtables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  xtables -A INPUT -p tcp --dport 22 -j ACCEPT

  # Accept ping requests
  if ask "Accept incoming 'ping' requests?" Y "CFG_firewall_accept_ping_requests";then
    sudo iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
  else
    [ "$ipv6_enable" = true ] && sudo ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j DROP
  fi
  # IPv6 accept all ICMPv6 packets
  [ "$ipv6_enable" = true ] && sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT

  # Set Random TCP port for SSH server
  if ask "Use a random TCP port for SSH server?" Y "CFG_firewall_change_ssh_port";then
    random_port=$(shuf -i 49152-65535 -n 1)
    input "Press enter or choose another TCP port for SSH" "$random_port" "CFG_firewall_ssh_port"
    new_port="$input_reply"
    wan_ipv4=$(ip -o a s "$public_iface" | grep global | awk '{print $4;exit}')
    sudo iptables -t nat -I PREROUTING -d "$wan_ipv4" -i "$public_iface" -p tcp -m tcp --dport 22 -j REDIRECT --to-port 65535
    sudo iptables -t nat -A PREROUTING -d "$wan_ipv4" -i "$public_iface" -p tcp -m tcp --dport "$new_port" -j REDIRECT --to-ports 22
    if [ "$ipv6_enable" = true ]; then
      wan_ipv6=$(ip -o -6 a s "$public_iface" | grep global | awk '{print $4;exit}')
      sudo ip6tables -t nat -I PREROUTING -d "$wan_ipv6" -i "$public_iface" -p tcp -m tcp --dport 22 -j REDIRECT --to-port 65535
      sudo ip6tables -t nat -A PREROUTING -d "$wan_ipv6" -i "$public_iface" -p tcp -m tcp --dport "$new_port" -j REDIRECT --to-ports 22
    fi
    print_warn "You can try to open another SSH session with the port: $new_port"
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

# Wireguard Setup
if ask "Install Wireguard?" Y "CFG_install_wireguard";then
  wg_enable=true
  wg_ipv4_enable=false
  wg_ipv6_enable=false
  wg_server_ips=""
  wg_fw_rule_up=""
  wg_fw_rule_down=""
  wg_peer_type=""

  input "Select Wireguard listening port" "51820" "CFG_wg_server_port"
  wg_server_port="$input_reply"

  # Selet server mode IPv4/IPv6/Dual stack
  if ask "Enable IPv4 support?" Y "CFG_wg_server_ipv4_enable";then
    wg_server_ips="${wg_server_ipv4}/24"
    wg_fw_rule_up="iptables -D FORWARD -j LOG; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -A FORWARD -j LOG; iptables -t nat -A POSTROUTING -o ${public_iface} -j MASQUERADE;"
    wg_fw_rule_down="iptables -D FORWARD -j LOG; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -A FORWARD -j LOG; iptables -t nat -D POSTROUTING -o ${public_iface} -j MASQUERADE;"
    # enable IPv4 forwarding
    sudo sysctl net.ipv4.ip_forward=1
    echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-wg.conf > /dev/null
    # firewall rules
    sudo iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -I INPUT -p udp -m udp --dport "${wg_server_port}" -m conntrack --ctstate NEW -j ACCEPT
    wg_peer_type="ip4"
    wg_ipv4_enable=true
  fi
  if ask "Enable IPv6 support?" Y "CFG_wg_server_ipv6_enable";then
    if [ "$wg_ipv4_enable" ]; then
      wg_server_ips=$wg_server_ips", ${wg_server_ipv6}/128"
      echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-wg.conf > /dev/null
    else
      wg_server_ips="${wg_server_ipv6}/128"
      echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee /etc/sysctl.d/99-wg.conf > /dev/null
    fi
    wg_fw_rule_up=$wg_fw_rule_up"ip6tables -D FORWARD -j LOG; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -A FORWARD -j LOG; ip6tables -t nat -A POSTROUTING -o ${public_iface} -j MASQUERADE;"
    wg_fw_rule_down=$wg_fw_rule_down"ip6tables -D FORWARD -j LOG; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -A FORWARD -j LOG; ip6tables -t nat -D POSTROUTING -o ${public_iface} -j MASQUERADE;"
    # enable IPv6 forwarding
    sudo sysctl net.ipv6.conf.all.forwarding=1
    # firewall rules
    sudo ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo ip6tables -I INPUT -p udp -m udp --dport "${wg_server_port}" -m conntrack --ctstate NEW -j ACCEPT
    wg_peer_type="ip6"
    wg_ipv6_enable=true
  fi
  [ "$wg_ipv4_enable" = false ] && [ "$wg_ipv6_enable" = false ] && die "Wireguard server mode: you should select IPv4 and/or IPv6"

  print_info "Install wireguard"
  install wireguard qrencode

  print_info "Generate server config"
  server_private_key=$(wg genkey)
  server_public_key=$(echo "${server_private_key}" | wg pubkey)

  cat > "${wg_server_cfg}" <<EOL
[Interface]
Address = ${wg_server_ips}
SaveConfig = true
ListenPort = ${wg_server_port}
PrivateKey = ${server_private_key}
PostUp = ${wg_fw_rule_up::-1}
PostDown = ${wg_fw_rule_down::-1}
EOL

  if [ "$non_interactive_mode" = true ]; then
    i=1
    for peer_type in "${CFG_wg_client_list[@]:?}"; do
      wg_create_client "$peer_type" "$i"
      i=$((i+1))
    done
  else
    i=1
    while ask "Create a peer client?" Y;do
      if [ "$wg_ipv4_enable" = true ] && [ "$wg_ipv6_enable" = true ]; then
        print_info "Choose the peer connectivity between IPv4, IPv6 or Dual stack"
        input "Please enter the peer client connectivity type (ip4|ip6|dual)" "dual"
        wg_peer_type="$input_reply"
      fi
      wg_create_client "$wg_peer_type" "$i"
      i=$((i+1))
    done
  fi

  print_info "Move server config to /etc/wireguard/"
  sudo mkdir -p "/etc/wireguard"
  sudo mv "$DIR"/${wg_server_cfg} /etc/wireguard/
  sudo chown root:root /etc/wireguard/${wg_server_cfg}
  sudo chmod 600 /etc/wireguard/${wg_server_cfg}

  print_info "Enable wireguard systemctl service"
  sudo systemctl enable wg-quick@wg0
  print_info "Save firewall rules"
  sudo netfilter-persistent save
  print_info "Restart wireguard systemctl service"
  sudo systemctl restart wg-quick@wg0

  # show the configuration
  print_info "wg show:"
  sudo wg show
  for client in "$DIR"/wg-client*.conf; do
    print_info "Client configuration '$client':"
    qrencode -t ansiutf8 < "$client"
  done
fi

# Install Docker
if ask "Install Docker?" Y "CFG_install_docker";then
  print_info "Add docker repository"
  install apt-transport-https ca-certificates software-properties-common
  curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" | sudo apt-key add -
  sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
  print_info "Install Docker"
  sudo apt update
  install docker-ce
  print_info "Add ${USER} to the docker group"
  sudo usermod -aG docker "${USER}"

  # Install docker-compose
  if ask "Install Docker Compose?" Y "CFG_install_docker_compose"; then
    print_info "Download latest docker-compose binary"
    tag=$(get_github_latest_release "docker/compose")
    mkdir -p ~/.docker/cli-plugins/
    sudo curl -L "https://github.com/docker/compose/releases/download/${tag}/docker-compose-$(uname -s)-$(uname -m)" -o ~/.docker/cli-plugins/docker-compose
    sudo chmod +x ~/.docker/cli-plugins/docker-compose
    print_info "Check the version"
    docker compose version

    if ask "Create a systemd unit for docker-compose services?" Y "CFG_docker_compose_systemd_unit";then
      docker_compose_systemd_unit=true
      sudo cp "$DIR"/docker-compose@.service /etc/systemd/system/
      sudo systemctl daemon-reload
      sudo mkdir -p /etc/docker-compose
    fi

    # Install Docker Pi-hole DNS server
    if ask "Install Pi-hole as a docker-compose service?" Y "CFG_install_docker_pihole";then
      sudo mkdir -p /etc/docker-compose/pi-hole
      print_info "Download docker-compose.yml"
      tag=$(get_github_latest_release "pi-hole/docker-pi-hole")
      curl -sL "https://raw.githubusercontent.com/pi-hole/docker-pi-hole/${tag}/docker-compose.yml.example" -o "$DIR"/pi-hole.docker-compose.yml
      input "Choose a password for Pi-hole Web interface (hidden)" "" "password" "CFG_pihole_web_interface_password"
      sed -i "s|# WEBPASSWORD:.*|WEBPASSWORD: '$input_reply'|g" "$DIR"/pi-hole.docker-compose.yml
      tz=$(cat /etc/timezone)
      sed -i "s|TZ: .*|TZ: '$tz'|g" "$DIR"/pi-hole.docker-compose.yml

      print_info "Disable systemd-resolved stub resolver"
      sudo sed -i "s|#DNSStubListener=yes|DNSStubListener=no|g" /etc/systemd/resolved.conf
      sudo rm /etc/resolv.conf
      sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
      sudo systemctl restart systemd-resolved

      print_info "Add firewall rules to prevent external public access to Pi-hole"
      # Stop wireguard before changing the firewall rules
      if [ "$wg_enable" = true ]; then
        sudo systemctl stop wg-quick@wg0
      fi
      sudo systemctl stop docker
      sudo netfilter-persistent restart
      sudo iptables -N DOCKER-USER
      sudo iptables -I FORWARD -j DOCKER-USER
      sudo iptables -A DOCKER-USER -i "${public_iface}" -p udp -m conntrack --ctorigdstport 53 --ctdir ORIGINAL -j DROP
      sudo iptables -A DOCKER-USER -i "${public_iface}" -p tcp -m conntrack --ctorigdstport 53 --ctdir ORIGINAL -j DROP
      sudo iptables -A DOCKER-USER -i "${public_iface}" -p tcp -m conntrack --ctorigdstport 80 --ctdir ORIGINAL -j DROP
      if ask "Disable Pi-hole DHCP server?" Y "CFG_pihole_dhcp_server_disable";then
        sed -i "/- \"67:67\/udp\"/d" "$DIR"/pi-hole.docker-compose.yml
      else
        sudo iptables -A DOCKER-USER -i "${public_iface}" -p udp -m conntrack --ctorigdstport 67 --ctdir ORIGINAL -j DROP
      fi
      sudo iptables -A DOCKER-USER -j RETURN
      sudo netfilter-persistent save
      sudo systemctl start docker
      # Restart wireguard after changing the firewall rules
      if [ "$wg_enable" = true ]; then
        sudo systemctl start wg-quick@wg0
      fi

      sudo cp pi-hole.docker-compose.yml /etc/docker-compose/pi-hole/docker-compose.yml
      rm pi-hole.docker-compose.yml

      if [ "$docker_compose_systemd_unit" = true ]; then
        print_info "Enable Pi-hole systemd unit"
        sudo systemctl enable docker-compose@pi-hole
        print_info "Start Pi-hole docker-compose"
        sudo systemctl start docker-compose@pi-hole
      else
        print_warn "Start Pi-hole docker compose manually"
        docker compose -p pihole -f /etc/docker-compose/pi-hole/docker-compose.yml pull
        docker compose -p pihole -f /etc/docker-compose/pi-hole/docker-compose.yml up -d
      fi
      print_info "Add Pi-hole nameserver to resolv.conf"
      sudo sed -i "/set-name.*/a \            nameservers:\n                addresses: [127.0.0.1]"  /etc/netplan/50-cloud-init.yaml
      sudo netplan apply
      print_info "Pi-hole version:"
      sudo docker exec -it  pihole pihole -v -c
    fi

    # Install docker-apps
    if ask "Install Docker services from 'docker-apps' directory?" Y "CFG_install_docker_apps";then
      for dir in "$DIR"/docker-apps/*; do
        if [ -d "$dir" ]; then
          app=$(echo "$dir" | rev | cut -d'/' -f1 | rev)
          print_info "Install '$app':"
          sudo cp -r "$dir" /etc/docker-compose/
          if [ "$docker_compose_systemd_unit" = true ]; then
            print_info " - enable systemd unit"
            sudo systemctl enable docker-compose@"$app"
            print_info " - start docker-compose"
            sudo systemctl start docker-compose@"$app"
          fi
        fi
      done
    fi
  fi
fi
