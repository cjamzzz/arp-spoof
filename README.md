# ARP Spoofer — README

> Small educational ARP spoofing proof-of-concept built with **Scapy**.  
> **IMPORTANT:** only run this in a controlled lab or on networks where you have **explicit permission**. I am not responsible for any damages you cause!


## Background

ARP is a protocol that maps MAC addresses to IP addresses in a network. 

Any device connected to the Internet or a local network uses MAC addresses to communicate with another device. So to send a packet to a given IP address, you first need its MAC address.

To do this you send an ARP packet, asking essentially:

```
Who has IP address 192.168.2.1?
```

The device that has an interface with that IP address answers:

```
I'm 192.168.2.1 and my MAC address is 12:34:56:78:90:ab!
```

You can now send the IP packet to the MAC address.

However this protocol is vulnerable to spoofing, and we can use this to temporarily disconnect devices from the Internet.

An easy way to do it is to send a targeted ARP packet to a victim, that replaces the MAC address of the gateway by another one.

Upon receival, any packet from the victim that goes to the router (basically any packet in a 802.11 network) is redirected to a wrong MAC address, and thus never gets to its destination correctly. 

The victim is **not** disconnected from the router : this is not a de-auth attack, however it will temporarily make all websites unavailable.

---

## Quick start

1. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv      
source .venv/bin/activate
```

2. Install the dependency:
```bash
pip install scapy
```

3. Run the script as root (example):

    `sudo python arp_spoof.py -t 192.168.2.115 -g 192.168.2.1 -i wlan0`

Stop with Ctrl+C — the script will attempt to restore ARP entries on exit.

---

## Command line options

- `-t, --target` : Target IP (victim) — required.  
- `-g, --gateway` : Gateway IP — required.  
- `-i, --iface` : Interface to use (default: `wlan0`).  
- `--target-mac` : Target MAC (optional; resolved automatically if not supplied).  
- `--gateway-mac` : Gateway MAC (optional; resolved automatically if not supplied).

---

## Requirements & environment

- Python 3.8+
- `scapy` (install with `pip install scapy`).  
- Must run with root privileges or `CAP_NET_RAW` capability (e.g. `sudo`) to send raw frames.  
- The attacker machine must be on the same L2 network (same subnet, same AP or switch) as target and gateway.  

---

## References

- Scapy documentation — https://scapy.net  
