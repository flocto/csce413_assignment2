#!/usr/bin/env python3

import threading

from http_honeypot import run_http_honeypot
from ssh_honeypot import run_ssh_honeypot


def run_honeypot():
    t1 = threading.Thread(target=run_http_honeypot, daemon=True)
    t2 = threading.Thread(target=run_ssh_honeypot, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


if __name__ == "__main__":
    run_honeypot()
