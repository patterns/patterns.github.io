# OpenBSD PF Router

[=> OpenBSD PF Router Build](https://www.openbsd.org/faq/pf/example1.html)
[=> Home Router Build](https://hackaday.com/2018/04/12/building-the-perfect-home-router/)
[=> Ars Linux Router Build](https://arstechnica.com/gadgets/2016/04/the-ars-guide-to-building-a-linux-router-from-scratch/)
[=> Router7 Build](https://michael.stapelberg.ch/posts/2021-07-10-linux-25gbit-internet-router-pc-build/)

## §1 /Networking
Used the guide exactly to set hostname.em0 for autoconf. Partly to make sure the uplink would work. Ultimately, like the Router7 article, the lease would change rarely allowing it to be safe to use a pseudo-static address config.

This is also related to the DNS record that we expose for the public gemini hostname. Ideally, we want to do DynDNS setup, but at this time it's skipped.

## §2 /Firewall
Followed exactly as shown in the guide. The line to pass traffic to the web server is adjusted for the Let's Encrypt configuration. Afterwards, we omit it and have a similar rule for port 1965 to allow gemini requests.

To check the configuration before applying:
```
# pfctl -n -f /etc/pf.conf
```

## §3 /DNS
Follow the guide. The one addition we make is inclusion of Oznu's NXDOMAIN list to sinkhole ads.

```
#### file: /var/unbound/etc/unbound.conf
        include: /var/unbound/etc/unbound.bl
forward-zone:
        name: "."
        forward-addr: 1.1.1.1
```

## §4 /Equipment
We had a regular D-Link ethernet hub that was good to go from the OpenBSD box and expand out to 8 more ports. This saved us from needing an expansion card or purchasing a hub brand new.

Not as power efficient as the SOC options. So when summer rolls around and temps rise, it may be important to investigate the NanoPi again.

=====

## * Notes, Lessons, Monologue
* Why? Our EdgeRouter Lite stopped working. Similar to one of the articles, we thought about buying a replacement and for some period we swapped in the wifi router in dual role of uplink and wifi access. After reading and searching, very close to ordering the NanoPi R4S. Then saw our under utilized old NAS server which ran SmartOS from Joyent. Also a build from Ars guides.
* OpenBSD? This was our favorite OS in the distant past (95/96?) and we revisited before until it wasn't convenient to run your own SMTP/DNS/HTTPD server. It still seems as good as ever, if not better (has ARM support in the field).
* Unbound? We have a todo to revisit and try its native versus the DNSCrypt Proxy's upstream TLS connections.

_________________________________________
2022 興怡 | Always wrong, sometimes lucky

