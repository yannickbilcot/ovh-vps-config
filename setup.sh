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
      echo -ne "\e[32m$1$prompt: \e[0m"
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


# Git configuration
print_info "Install gitconfig"
#cp gitconfig ~/.gitconfig

# Change user password
print_info "Change user '$(whoami)' password"
#passwd

# Enable IPv6
print_info "Enable IPv6 network"
if ask "Do you have a public IPv6?" Y;then
  input "Enter the IPv6 address"
  echo $input_reply
  input "Enter the IPv6 gateway"
  echo $input_reply
fi
