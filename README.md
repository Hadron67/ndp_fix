# ndp_fix
Respond all ipv6 neighbor solicitation messages in MacOS.

To compile and run:
```sh
gcc -o ndp_fix ndp_fix.c
sudo ./ndp_fix
```
Because it uses raw socket, `sudo` is required.

## Why
MacOS does not respond neighbor solicitations with global source addresses (see [here](https://discussions.apple.com/thread/8620806) and [here](https://forum.openwrt.org/t/how-to-send-icmp6-neighbor-solicitation-with-a-link-local-source-address/53220)). So if the router uses global source address for neighbor descovery protocol it will be unable to get the device's MAC address and cannot forward packets to it, even if the device has successfully configured a global ipv6 address via SLAAC or DHCPv6.
