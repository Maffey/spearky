import kivy
from kivy.app import App
from kivy.core.window import Window
from kivy.properties import ObjectProperty
from kivy.uix.widget import Widget

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')


class MainMenu(Widget):
    detection = ObjectProperty(None)
    escalation = ObjectProperty(None)
    penetration = ObjectProperty(None)


class ChangeMAC(Widget):
    # Initialize widgets of the class taken from .kv file.
    mac_input = ObjectProperty(None)

    def submit_mac_callback(self):
        print(f"Your MAC address: {self.mac_input.text}")
        self.mac_input.text = ""


class SpearkyApp(App):

    def build(self):
        menu_window = ChangeMAC()
        return menu_window


if __name__ == '__main__':
    SpearkyApp().run()
