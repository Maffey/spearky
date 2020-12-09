"""network_scanner.py - network scanner which uses Scapy to find out info about a network."""

import scapy.all as scapy


def scan(ip):
    """Scan network by sending ARP requests to desired IP addresses.

    Return a list of devices with their associated MAC and IP addresses.
    Works with IP ranges, using mask, which must be added after IP address like this: IP/mask.
    For example: 192.168.0.0/24
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_frame / arp_request
    answered = scapy.srp(arp_packet, timeout=1, verbose=False)[0]

    clients_list = []
    for answer in answered:
        client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
