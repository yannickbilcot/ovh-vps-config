# ovh-vps-config
OVH VPS configuration for Ubuntu 20.04

![alt text](https://github.com/yannickbilcot/ovh-vps-config/raw/master/banner.png "Banner")

### Quickstart

```bash
git clone https://github.com/yannickbilcot/ovh-vps-config.git
cd ovh-vps-config
./setup.sh
```
#### Non-interactive mode
- Edit the configuration file 'setup.cfg'
- Start the script with the option '-a'

```bash
./setup.sh -a
```

## VPS Configuration

- [x] GIT configuration
- [x] Change default user password
- [x] Create and delete user(s)
- [x] Setup the server timezone
- [x] Setup the server hostname and FQDN
- [x] Enable IPv6
- [x] Setup IPv6 Firewall
- [x] Setup IPv4 Firewall
- [x] Setup PSAD (Port Scan Attack Detection)
- [x] Setup APT automatic update/upgrade

- [x] Setup email alerts
  - [x] alert after server reboot
  - [x] alert on SSH login

- [x] SSH configuration
  - [x] Authentication via SSH keys
  - [x] Disable password authentication
  - [x] Redirect a random TCP port to port 22
  - [x] Setup fail2ban for SSH
  - [x] Enable 2FA (google authenticator)

- [x] Setup Wireguard
  - [x] IPv4, IPv6 or Dual stack support
  - [x] Can create multiple peer(s)
  - [x] Firewall configuration

- [x] Install Docker environment
  - [ ] Add IPv6 support 
- [x] Install pihole (DNS server)
- [ ] Create a Webpage dashboard with link to all the web services (with subdomains)
- [ ] Open a WAN port for Torrent
- [ ] Install V2Ray

### Useful commands for debug:

* Wireguard
```bash
echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control
```
* Firewall logging
```bash
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A LOGGING -j DROP
journalctl -f
```
