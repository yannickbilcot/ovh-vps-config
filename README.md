# ovh-vps-config
OVH VPS configuration for Ubuntu 20.04

![alt text](https://github.com/yannickbilcot/ovh-vps-config/raw/master/banner.png "Banner")

### Quickstart

```bash
git clone https://github.com/yannickbilcot/ovh-vps-config.git
cd ovh-vps-config
./setup.sh
```

## VPS Configuration

- [x] GIT configuration
- [x] Change default user password
- [x] Setup the server timezone
- [ ] Setup the server hostname and FQDN
- [x] Enable IPv6
- [ ] Setup IPv6 Firewall
- [ ] Setup IPv4 Firewall

- [x] Setup email alerts
  - [ ] alert after server reboot
  - [x] alert on SSH login

- [ ] SSH configuration
  - [x] Authentication via SSH keys
  - [x] Disable password authentication
  - [ ] Redirect a random tcp port to port 22 (iptables) (IPv4 + IPv6)
  - [x] Setup fail2ban for SSH
  - [x] Enable 2FA (google authenticator)


- [ ] Install Docker environment
- [ ] Install pihole (DNS server)
- [ ] Setup PSAD

- [ ] Setup Wireguard
  - [ ] Add IPv6 support (generate ULA address randomly)
  - [ ] Add a function to create a new Peer (IPv4 and/or IPv6)
  - [ ] Firewall configuration
  - [ ] IPv6 only support (DNS64 + Stateless [NAT66](https://www.jool.mx/en/intro-xlat.html#siit-traditional))
  
- [ ] Create a Webpage dashboard with link to all the web services (with subdomains)
- [ ] Open a WAN port for Torrent
- [ ] Display some helpers when logging via SSH
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
