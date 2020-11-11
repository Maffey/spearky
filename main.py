# Main imports
import kivy
import subprocess

# Specific imports from kivy
from kivy.app import App
from kivy.properties import ObjectProperty
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen

# Imports of the core functionality of the Spearky app.
import core.detection.packet_sniffer as packet_sniffer
import core.penetration.mac_changer as mac_changer
import core.penetration.arp_spoofer as arp_spoofer

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')

# TODO: Make exhaustive documentation of core scripts. Implement unit tests, input validation.


# The WindowManager class is responsible for properly changing Screens in the app.
class WindowManager(ScreenManager):
    """Coordinate all the Screen changes throughout the app."""
    pass


class MainMenuScreen(Screen):
    """Display the main menu of the app."""
    pass


class DetectionToolsScreen(Screen):
    """Display all the tools in Detection category."""
    pass


class SniffPacketsScreen(Screen):
    """Sniff packets asynchronously and find any potential """
    
    # TODO: Try to use a list of interfaces instead. Some way of getting interface names would be needed.
    # Resource: https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
    interface_input = ObjectProperty(None)
    terminal_output = ObjectProperty(None)
    found_credentials = ObjectProperty(None)
    sniffer = None

    def start_sniffing(self):
        interface = self.interface_input.text
        if interface == "":
            self.sniffer = packet_sniffer.create_sniffer()
        else:
            self.sniffer = packet_sniffer.create_sniffer(interface)
        self.sniffer.start()

        self.interface_input.text = ""
        print("[+] Sniffing has been started.")

    # TODO: implement continuous sniffing output in the future. Use Clock for this.
    def stop_sniffing(self):
        if self.sniffer.running:
            self.sniffer.stop()
            print("[+] Sniffing has been stopped.")
            with open("data/sniffing_log.txt", "r+") as log_file:
                self.terminal_output.text = log_file.read()
                log_file.truncate(0)
            with open("data/sniffing_credentials.txt", "r+") as log_file:
                self.found_credentials.text = log_file.read()
                log_file.truncate(0)
        else:
            show_feedback_popup("Packet Sniffing Warning",
                                "The packet sniffing has not yet started. It can't be stopped.")


class EscalationToolsScreen(Screen):
    pass


class PenetrationToolsScreen(Screen):
    pass


class ChangeMACScreen(Screen):
    # Initialize Widgets of the class taken from .kv file.
    mac_input = ObjectProperty(None)
    interface_input = ObjectProperty(None)
    original_mac = ObjectProperty(None)
    current_mac = ObjectProperty(None)

    # Default value for interface.
    current_interface = "eth0"

    def submit_mac(self):
        # Store inputs in additional variables to allow us to clear Text Inputs instantly.
        # TODO: Handle errors. Use default interface if none was provided. Add error popups.
        interface, mac_address = self.interface_input.text, self.mac_input.text
        self.current_interface = interface
        self.mac_input.text = ""
        self.interface_input.text = ""

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(interface, mac_address)
        show_feedback_popup("MAC Change Successful", "MAC change performed successfully.")

    def revert_mac(self):
        """Restores computer's MAC address to original one."""
        self.mac_input.text = ""
        self.interface_input.text = ""

        print("[+] Reverting MAC address...")

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(self.current_interface, self.original_mac.text)
        show_feedback_popup("MAC Reversing Successful", "MAC address has been restored to the original one.")


class SpoofARPScreen(Screen):
    target_input = ObjectProperty(None)
    gateway_input = ObjectProperty(None)
    status = ObjectProperty(None)

    # TODO: Add threading.
    def start_spoofing(self):
        self.status.text = "Running..."
        target, gateway = self.target_input.text, self.gateway_input.text
        self.target_input.text = ""
        self.gateway_input.text = ""
        arp_spoofer.perform_spoofing(target, gateway)
        show_feedback_popup("ARP Spoofing", "ARP spoofing has been started successfully.")


class SpearkyApp(App):
    pass


# The class below is the generic Popup Widget that will be used to provide user with feedback.
class FeedbackPopup(Popup):
    feedback_text = ObjectProperty(None)


# This method works with FeedbackPopup class. Creates Popup window based on a template with w
def show_feedback_popup(title, content_text, size=(350, 200)):
    popup = FeedbackPopup(title=title, size_hint=(None, None), size=size)
    popup.feedback_text.text = content_text
    popup.open()


# Runs when the App starts.
if __name__ == '__main__':
    subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    SpearkyApp().run()
