import kivy
from kivy.app import App
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.widget import Widget

import core.penetration.mac_changer as mac_changer

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')


# The WindowManager class is responsible for properly changing Screens in the app.
class WindowManager(ScreenManager):
    pass


class MainMenuScreen(Screen):
    pass


# TODO: implement some sort of feedback for user (i.e. toast pop-up)
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
        interface, mac_address = self.interface_input.text, self.mac_input.text
        self.current_interface = interface
        self.mac_input.text = ""
        self.interface_input.text = ""

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(interface, mac_address)

    def revert_mac(self):
        """Restores computer's MAC address to original one."""
        self.mac_input.text = ""
        self.interface_input.text = ""

        print("[+] Reverting MAC address...")

        # Change the Label's text of current MAC address while performing said change.
        self.current_mac.text = mac_changer.perform_mac_change(self.current_interface, self.original_mac.text)


class SpearkyApp(App):
    pass


if __name__ == '__main__':
    SpearkyApp().run()
