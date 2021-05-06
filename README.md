# ovh-vps-config
OVH VPS configuration for Ubuntu 20.04

### Quickstart

* Clone this repository

```bash
cd ovh-vps-config
chmod +x ./setup.sh
./setup.sh
```

## VPS Configuration

- [ ] GIT configuration
- [ ] Change default user password
- [ ] Enable IPv6
- [ ] Setup IPv6 Firewall
- [ ] Setup IPv4 Firewall
- [ ] SSH configuration
  - [ ] Authentication via SSH keys
  - [ ] Redirect a random tcp port to port 22 (iptables) (IPv4 + IPv6)
  - [ ] Setup fail2ban for SSH
  - [ ] Enable 2FA (google authenticator)
  

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
