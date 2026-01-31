#!/usr/bin/env python3

import os
import socket
import threading

import paramiko

from logger import create_logger

SSH_PORT = int(os.environ.get("HONEYPOT_SSH_PORT", "22"))
BANNER = os.environ.get(
    "HONEYPOT_SSH_BANNER", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
)
STATE = {"ip_counts": {}, "auth_counts": {}}

SCANNER_CLIENTS = ["libssh", "paramiko", "hydra", "nmap", "masscan", "zgrab", "shodan", "sshlib"]
COMMON_USERS = {"root", "admin", "test", "guest", "ubuntu", "user"}
COMMON_PASSWORDS = {"root", "admin", "password", "123456", "12345678", "qwerty", "letmein"}

HOST_KEY = paramiko.RSAKey.generate(2048)


class HoneyServer(paramiko.ServerInterface):
    def __init__(self, log, addr):
        self.log = log
        self.addr = addr

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        STATE["auth_counts"][self.addr[0]] = STATE["auth_counts"].get(self.addr[0], 0) + 1
        auth_tags = []

        if username in COMMON_USERS:
            auth_tags.append("common_username")
        if password in COMMON_PASSWORDS:
            auth_tags.append("weak_password")
        if STATE["auth_counts"][self.addr[0]] >= 3:
            auth_tags.append("bruteforce_suspected")
            
        self.log(
            {
                "type": "ssh_auth",
                "src_ip": self.addr[0],
                "username": username,
                "password": password,
                "tags": auth_tags,
            }
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.log(
            {
                "type": "ssh_auth",
                "src_ip": self.addr[0],
                "username": username,
                "pubkey_type": key.get_name(),
                "tags": ["publickey"],
            }
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle_conn(conn, addr, log):
    STATE["ip_counts"][addr[0]] = STATE["ip_counts"].get(addr[0], 0) + 1
    log({"type": "ssh_connect", "src_ip": addr[0], "src_port": addr[1]})
    transport = paramiko.Transport(conn)
    transport.local_version = BANNER
    transport.add_server_key(HOST_KEY)
    server = HoneyServer(log, addr)
    try:
        transport.start_server(server=server)
        client_banner = transport.remote_version or ""
        banner_tags = []

        cb = client_banner.lower()
        if not client_banner.startswith("SSH-"):
            banner_tags.append("non_ssh_probe")
        if any(x in cb for x in SCANNER_CLIENTS):
            banner_tags.append("scanner_client")

        log({"type": "ssh_banner", "src_ip": addr[0], "client": client_banner, "tags": banner_tags})
        transport.accept(10)
    except Exception:
        log({"type": "ssh_error", "src_ip": addr[0]})
    finally:
        transport.close()
        conn.close()


def run_ssh_honeypot():
    log = create_logger()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", SSH_PORT))
    sock.listen(100)
    log({"type": "start", "proto": "ssh", "port": SSH_PORT})
    while True:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_conn, args=(
            conn, addr, log), daemon=True)
        t.start()


if __name__ == "__main__":
    run_ssh_honeypot()
