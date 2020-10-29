import kivy
from kivy.app import App
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import ObjectProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.widget import Widget

# Ensure a proper version of kivy is installed.
kivy.require('1.11.1')


# The WindowManager class is responsible for properly changing Screens in the app.
class WindowManager(ScreenManager):
    pass


class MainMenuScreen(Screen):
    pass


class ChangeMACScreen(Screen):
    # Initialize widgets of the class taken from .kv file.
    mac_input = ObjectProperty(None)

    def submit_mac(self):
        print(f"Your MAC address: {self.mac_input.text}")
        self.mac_input.text = ""


class SpearkyApp(App):
    pass


if __name__ == '__main__':
    SpearkyApp().run()
