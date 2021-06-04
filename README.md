# ovh-vps-config
OVH VPS configuration for Ubuntu 20.04

[![Build Status](https://travis-ci.com/yannickbilcot/ovh-vps-config.svg?token=aHVjkgXdWt2jD9zBRVrU&branch=master)](https://travis-ci.com/yannickbilcot/ovh-vps-config)

![alt text](https://github.com/yannickbilcot/ovh-vps-config/raw/master/banner.png "Banner")

### Quickstart

```bash
git clone https://github.com/yannickbilcot/ovh-vps-config.git
cd ovh-vps-config
./setup.sh
```
#### Non-interactive mode installation
- Edit the configuration file 'setup.cfg'
- Start the script with the option '-a'

```bash
./setup.sh -a
```

## VPS Configuration
### Supported features

#### Software
* Software update and upgrade
* Set the server local timezone
* Set the server hostname and FQDN

#### User
* Change default user password
* Create and delete user(s)

#### Networking
* Setup IPv6 network (static address)

#### SSH configuration
* Enable 2FA authentication (google authenticator)
* Enable authentication via SSH keys
* Open a random port for SSH service on external interface

#### Firewall
* Simple stateful firewall configuration with iptables
* External opened ports limited to SSH and WireGuard service
* Setup IPv4 & IPv6 firewall

#### Security
* Install [PSAD](http://cipherdyne.org/psad/) (Port Scan Attack Detection)
* Install [fail2ban](https://github.com/fail2ban/fail2ban) to protect SSH

#### Email notifications
* Install Postifx used as SMTP relay server with Gmail
* Supported alerts:
  * on SSH login
  * after a system reboot
  * on software unattended security update
  * on port scan detection (PSAD)

#### WireGuard VPN
* Install [WireGuard](https://www.wireguard.com/)
* IPv4, IPv6 or dual stack support
* Can create multiple peers

#### Docker services
* Install [Docker](https://www.docker.com/) environment
* Install docker-compose
* Install [Pi-hole](https://github.com/pi-hole/pi-hole) (DNS server)
* Can install additional docker services from "docker-apps" subdirectory
