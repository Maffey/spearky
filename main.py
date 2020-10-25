import kivy
from kivy.app import App
from kivy.core.window import Window
from kivy.uix.widget import Widget

# Ensures a proper version of kivy is installed.
kivy.require('1.11.1')

# Changes the rendered size of the window.
Window.size = (500, 32)


class ChangeMAC(Widget):
    pass


class SpearkyApp(App):

    def build(self):
        menu_window = ChangeMAC()
        return menu_window


if __name__ == '__main__':
    SpearkyApp().run()
