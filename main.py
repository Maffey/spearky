"""Spearky - penetration testing app with GUI developed in Kivy."""

# Common modules
import subprocess

# Kivy module
import kivy
from kivy.app import App
from kivy.clock import Clock
from kivy.properties import ObjectProperty
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen

# Modules containing the core functionality of the Spearky app.
import core.penetration.mac_changer as mac_changer
import core.penetration.arp_spoofer as arp_spoofer
from core.detection.packet_sniffer import PacketSniffer

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')

# TODO: Make exhaustive documentation of core scripts. Implement unit tests, input validation.


# The WindowManager class is responsible for properly changing Screens in the app.
class WindowManager(ScreenManager):
    """Coordinate all the Screens and changes between them throughout the app."""
    pass


class MainMenuScreen(Screen):
    """Display the main menu of the app."""
    pass


class DetectionToolsScreen(Screen):
    """Display all the tools in Detection category."""
    pass


class SniffPacketsScreen(Screen):
    """Sniff packets asynchronously and find any potential login credentials.

    Attributes:
        interface_input - Text Input for entering network interface
        terminal_output - Text Input for displaying output from terminal
        found_credentials - Text Input for displaying credentials found in terminal's output

    Methods:
        start_sniffing() - run after pressing "Sniff" Button
        stop_sniffing() - run after pressing "Stop" Button
    """
    
    # TODO: Try to use a list of interfaces instead. Some way of getting interface names would be needed.
    # Resource: https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
    interface_input = ObjectProperty(None)
    terminal_output = ObjectProperty(None)
    found_credentials = ObjectProperty(None)
    sniffer = PacketSniffer()
    # update_event = Clock.schedule_interval(update_output_fields)

    def start_sniffing(self):
        """Start sniffing by either using default interface (eth0) or the one provided by the user."""
        # Clear text fields for displaying output.
        self.terminal_output.text, self.found_credentials.text = "", ""

        # Store inputted interface in a variable.
        interface = self.interface_input.text
        # Clear text in interface field.
        self.interface_input.text = ""

        # If user provided no variable, use default one (eth0)
        if interface == "":
            self.sniffer = PacketSniffer()
        else:
            self.sniffer = PacketSniffer(interface=interface)

        # Start sniffing by calling scapy's AsyncSniffer contained in PacketSniffer object.
        self.sniffer.start_sniffer()

        # Schedule an update of displayed text fields every second.
        # NOTE: This most likely doesn't stop after stopping sniffing and might use resources unnecessarily.
        Clock.schedule_interval(self.update_output_fields, 1)

        # Display information to user that sniffing has been started.
        print("[+] Sniffing has been started.")
        show_feedback_popup("Packet Sniffing Started", "Sniffing packets has been started.")

    # TODO: implement continuous sniffing output in the future. Use Clock for this.
    def stop_sniffing(self):
        """Stop sniffing or display message indicating that sniffer hasn't been started yet."""
        # If PacketSniffer is running, stop it, display final output in the text fields
        # and clear PacketSniffer's attributes containing said output.
        # If it isn't running, display appropriate message.
        if self.sniffer.is_running():
            self.sniffer.stop_sniffer()
            print("[+] Sniffing has been stopped.")
            self.terminal_output.text += "\n".join(self.sniffer.console_output) + "\n"
            self.found_credentials.text += "\n".join(self.sniffer.credentials) + "\n"
            self.sniffer.console_output, self.sniffer.credentials = [], []
        else:
            show_feedback_popup("Packet Sniffing Warning",
                                "The packet sniffing has not yet started. It can't be stopped.")

    def update_output_fields(self, dt):
        """Update output fields with found information and clear PacketSniffer's attributes."""
        # If there's content stored in console_output, display it in the text fields.
        if self.sniffer.console_output:
            self.terminal_output.text += "\n".join(self.sniffer.console_output) + "\n"
            self.sniffer.console_output = []
        # If there's content stored in credentials, display it in the text fields.
        if self.sniffer.credentials:
            self.found_credentials.text += "\n".join(self.sniffer.credentials) + "\n"
            self.sniffer.credentials = []


class EscalationToolsScreen(Screen):
    """Display all the tools in Escalation category."""
    pass


class PenetrationToolsScreen(Screen):
    """Display all the tools in Penetration category."""
    pass


class ChangeMACScreen(Screen):
    """Change current MAC address to the one inputted. Display default MAC address and possibly, revert the changes."""
    # Initialize Widgets of the class taken from .kv file.
    mac_input = ObjectProperty(None)
    interface_input = ObjectProperty(None)
    original_mac = ObjectProperty(None)
    current_mac = ObjectProperty(None)

    # Default value for interface.
    current_interface = "eth0"

    def submit_mac(self):
        """Take strings from input fields and use them as arguments for performing MAC address change."""
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
        """Restores computer's MAC address to the original one."""
        self.mac_input.text = ""
        self.interface_input.text = ""

        print("[+] Reverting MAC address...")

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(self.current_interface, self.original_mac.text)
        show_feedback_popup("MAC Reversing Successful", "MAC address has been restored to the original one.")


class SpoofARPScreen(Screen):
    """Spoof ARP table and display the process' status to the user."""
    target_input = ObjectProperty(None)
    gateway_input = ObjectProperty(None)
    status = ObjectProperty(None)

    # TODO: Add threading.
    def start_spoofing(self):
        """Start spoofing ARP table between chosen targets."""
        self.status.text = "Running..."
        target, gateway = self.target_input.text, self.gateway_input.text
        self.target_input.text = ""
        self.gateway_input.text = ""
        arp_spoofer.perform_spoofing(target, gateway)
        show_feedback_popup("ARP Spoofing", "ARP spoofing has been started successfully.")


class SpearkyApp(App):
    """Root class that represents the whole App."""
    pass


class FeedbackPopup(Popup):
    """Generic Popup that is used to provide user with feedback."""
    feedback_text = ObjectProperty(None)


def show_feedback_popup(title, content_text, size=(350, 200)):
    """Create FeedbackPopup based on provided arguments and display it."""
    popup = FeedbackPopup(title=title, size_hint=(None, None), size=size)
    popup.feedback_text.text = content_text
    popup.open()


# Run when App starts.
if __name__ == '__main__':
    subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    SpearkyApp().run()
