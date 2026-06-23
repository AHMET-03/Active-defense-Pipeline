import os
import json
import socket
import threading
import time
from datetime import datetime
import paramiko
from cti_enrichment import enrich_ip_telemetry

HOST_KEY = paramiko.RSAKey.generate(2048)
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 2222
LOG_FILE = "Honeypot_telemetry.json"

class MediumInteractionSSH(paramiko.ServerInterface):
    def __init__ (self, client_ip):
     self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_event(self.client_ip, "login_attempt", {"username": username, "password": password}, "T1110")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

def log_event(ip, event_type, data, mitre_tag):
    #Call for enrichment function to gather attacker's information
    cti_data = enrich_ip_telemetry(ip)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": ip,
        "event_type": event_type,
        "intel": cti_data, 
        "data": data,
        "mitre_technique": mitre_tag
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
        print(f"[*] ENRICHED ALERT ({mitre_tag}): {ip} [{cti_data['isp']}] -> {data}")

def handle_shell(channel, client_ip):
    motd = f"""
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: {time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime())} from 192.168.1.105
root@ubuntu-server:~# """
    
    channel.send(motd.encode('utf-8'))
    
    command_buffer = ""
    while True:
        try:
            char = channel.recv(1).decode('utf-8')
            if not char:
                break
            
            if char in ('\r', '\n'):
                channel.send('\r\n'.encode('utf-8'))
                cmd = command_buffer.strip()
                if cmd:
                    log_event(client_ip, "command_executed", {"command": cmd}, "T1059")
                    
                    if cmd == "whoami":
                        channel.send(b"root\r\n")
                    elif cmd == "id":
                        channel.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                    elif cmd == "ls":
                        channel.send(b"snap  syslog.bak  user.txt\r\n")
                    elif cmd in ("exit", "quit"):
                        break
                    else:
                        channel.send(f"-bash: {cmd.split()[0]}: command not found\r\n".encode('utf-8'))
                
                command_buffer = ""
                channel.send(b"root@ubuntu-server:~# ")
            
            elif char in ('\x08', '\x7f'):
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    channel.send(b'\x08 \x08')
            
            else:
                command_buffer += char
                channel.send(char.encode('utf-8'))
        except Exception:
            break
    channel.close()

def handle_connection(client_socket, client_address):
    client_ip = client_address[0]
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = MediumInteractionSSH(client_ip)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        channel = transport.accept(20)
        if channel:
            handle_shell(channel, client_ip)
            
    except Exception as e:
        pass
    finally:
        transport.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        server_socket.listen(100)
        print(f"[+] Active Defense Sensor Online.")
        print(f"[+] Simulated OS: Ubuntu 22.04")
        print(f"[+] Listening for targets on port {LISTEN_PORT}...")
    except Exception as e:
        print(f"[-] Binding failed: {e}")
        return

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_connection, args=(client_socket, client_address), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[-] Shutting down sensor.")
            break

if __name__ == "__main__":
    main()
