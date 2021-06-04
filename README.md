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
* All the externals ports are closed by default except for SSH and WireGuard service
* Setup IPv4 firewall
* Setup IPv6 firewall

#### Security
* Setup [PSAD](http://cipherdyne.org/psad/) (Port Scan Attack Detection)
* Setup [fail2ban](https://github.com/fail2ban/fail2ban) to protect SSH

#### Email alerts
* Install Postifx used as SMTP relay server for Gmail
** alert on SSH login
** alert after a system reboot
** alert on APT unattended security update
** alert for PSAD service

#### WireGuard VPN
* Install WireGuard
** IPv4, IPv6 or dual stack support
** Can create multiple peer(s)

#### Docker services
* Install Docker environment
* Install docker-compose
** Install Pi-hole (DNS server)
** Can install additional docker services from "docker-apps" subdirectory
