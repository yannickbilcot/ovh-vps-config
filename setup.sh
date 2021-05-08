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
      read -r input_reply </dev/tty
      if [[ -z $input_reply ]]; then
          input_reply=$default
      fi
      if [[ -n $input_reply ]];then
        return
      fi
  done

}
############################################################

# function to setup SSH key authentication
function setup_ssk_key() {
  print_info "Generate a SSH key pair on client side with 'ssh-keygen'"
  input "Copy-paste the client public key (id_rsa.pub) just here"
  mkdir -p ~/.ssh
  echo "${input_reply}" >> ~/.ssh/authorized_keys
  chmod -R go= ~/.ssh
  print_info "==> Open another SSH session to test the SSH Key authentication"
  print_warn "==> But do not close this SSH session!!!"
  if ! ask "Is the authentication via SSH key working correctly?";then
    die "SSH key authentication doesn't work, abort this program"
  fi
}

############################################################
# main
############################################################
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
  print_info "apt upgrade"
  sudo apt -y upgrade
fi

# Git configuration
if ask "Setup Git configuration?" Y;then
  print_info "Git setup"
  sudo apt -y install git
  cp gitconfig ~/.gitconfig
  input "Enter your Git username" "John Doe"
  git config --global user.name "${input_reply}"
  input "Enter your Git email" "john.doe@mail.com"
  git config --global user.email "${input_reply}"
  git config --global credential.username "${input_reply}"
fi

# Change user password
if ask "Do you want to change current user password?" Y;then
  passwd
fi

# Enable IPv6
if ask "Do you have a public IPv6 address?" Y;then
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
fi

# Enable SSH 2FA
if ask "Do you want to enable SSH 2FA ?" Y;then
  print_info "install google-authenticator"
  sudo apt -y install libpam-google-authenticator
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
  cp sshd.bak sshd
  echo "auth required pam_google_authenticator.so nullok" >> sshd
  echo "auth required pam_permit.so" >> sshd
  sudo cp sshd /etc/pam.d/sshd
  rm sshd
  if [ ! -f sshd_config.bak ]; then
    sudo cp /etc/ssh/sshd_config sshd_config.bak
  fi
  cp sshd_config.bak sshd_config
  sed -i "s|^ChallengeResponseAuthentication.*$|ChallengeResponseAuthentication yes|g" sshd_config
  sudo cp sshd_config /etc/ssh/sshd_config
  rm sshd_config
  sudo systemctl restart sshd.service
  print_info "Please save the TOTP information above in 'Google Authenticator' alike app"
  print_info "==> Open another SSH session to test the 2FA authentication"
  print_warn "==> But do not close this SSH session!!!"
  if ! ask "Is the 2FA authentication working correctly?";then
    die "SSH 2FA doesn't work, abort this program"
  fi
fi

# Setup SSH Keys
if ask "Do you want to enable authentication via SSH keys?" Y;then
  setup_ssk_key
  while ask "Do you want to add another SSH key client?";do
    setup_ssk_key
  done
fi
