import threading
import paramiko
import socket
import logging
import sys
import os

from core.database import Attack, get_db_session
from core.mitre_mapper import map_command_to_mitre

# Temporary keys for the server
HOST_KEY = paramiko.RSAKey.generate(2048)

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Accept ALL passwords
        print(f"[SSH] Accepted login from {self.client_ip} as {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

import uuid
import hashlib
from core.threat_intel import ti_provider

def handle_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        server = SSHServer(addr[0])
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            return
            
        channel = transport.accept(20)
        if channel is None:
            return
            
        server.event.wait(10)
        if not server.event.is_set():
            return
            
        channel.send("Ubuntu 22.04.2 LTS\r\n\r\n")
        channel.send("root@server:~# ")
        
        command_buffer = ""
        session_id = str(uuid.uuid4())
        intel = ti_provider.get_ip_reputation(addr[0])
        
        while True:
            char = channel.recv(1)
            if not char:
                break
                
            try:
                char = char.decode('utf-8')
            except:
                continue

            if char == '\r':
                channel.send("\r\n")
                cmd = command_buffer.strip()
                if cmd:
                    print(f"[SSH] Command from {addr[0]}: {cmd}")
                    
                    # Log attack
                    session = get_db_session()
                    # Fake location for local demo if 127.0.0.1
                    geo = "Unknown"
                    if addr[0] == "127.0.0.1":
                        geo = "Localhost"

                    file_hash = None
                    if "wget" in cmd or "curl" in cmd:
                        file_hash = hashlib.sha256(cmd.encode()).hexdigest()

                    attack = Attack(
                        session_id=session_id,
                        source_ip=addr[0],
                        geo_location=geo,
                        port=2222,
                        protocol="SSH",
                        payload=cmd,
                        mitre_tags=map_command_to_mitre(cmd),
                        risk_score=intel["risk_score"],
                        threat_label=intel["threat_label"],
                        file_hash=file_hash
                    )
                    session.add(attack)
                    session.commit()
                    session.close()

                    if cmd in ['exit', 'quit']:
                        channel.close()
                        break
                        
                    # Fake response
                    if cmd == 'whoami':
                        channel.send("root\r\n")
                    else:
                        channel.send(f"bash: {cmd}: command not found\r\n")
                        
                command_buffer = ""
                channel.send("root@server:~# ")
            elif char == '\x03': # Ctrl+C
                channel.send("^C\r\nroot@server:~# ")
                command_buffer = ""
            elif char == '\x7f': # Backspace
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    channel.send('\b \b')
            else:
                command_buffer += char
                channel.send(char)

    except Exception as e:
        print(f"[SSH Error] {e}")
    finally:
        client.close()

def start_ssh_honeypot(port=2222):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        print(f"[*] SSH Honeypot listening on port {port}")
        
        while True:
            client, addr = sock.accept()
            print(f"[*] Connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_connection, args=(client, addr)).start()
            
    except Exception as e:
        print(f"[-] Failed to bind SSH port {port}: {e}")

if __name__ == "__main__":
    start_ssh_honeypot()
