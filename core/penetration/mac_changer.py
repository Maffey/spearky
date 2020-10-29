#! /usr/bin/env python3
# mac_changer.py - simple MAC address changer for network interfaces.
# Compatibility: Python 3.x

import subprocess
import re


# TODO: implement unit tests, input validation

def change_mac(interface: str, mac_address: str) -> None:
    print(f"[+] Changing the MAC address for {interface} to {mac_address}")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", mac_address])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface: str = "eth0") -> str:
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)", str(ifconfig_result))
    if mac_address_search_result is not None:
        return mac_address_search_result.group()
    else:
        print("[-] Could not read a MAC address.")


def get_original_mac(interface: str = "eth0") -> str:
    ethtool_result = subprocess.check_output(["ethtool", "-P", interface])
    mac_address_search_result = re.search(r"(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)", str(ethtool_result))
    if mac_address_search_result is not None:
        return mac_address_search_result.group()
    else:
        print("[-] Could not read a MAC address.")


def perform_mac_change(interface: str, mac_address: str) -> str:
    current_mac = get_current_mac(interface)
    print(f"[+] Current MAC: {current_mac}")
    change_mac(interface, mac_address)
    current_mac = get_current_mac(interface)
    if current_mac == mac_address:
        print("[+] The MAC address change have been performed successfully.")
        print(f"[+] Your new MAC is {current_mac}.")
        return current_mac
    else:
        print("[-] Operation failed. MAC address has not been changed.")
        return "Error"
