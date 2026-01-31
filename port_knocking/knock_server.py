#!/usr/bin/env python3
"""Starter template for the port knocking server."""
import threading
import subprocess
import argparse
import logging
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [14687, 21353, 4331, 5678]
DEFAULT_DUMMY_PORTS = [25473, 1633, 8123]
DEFAULT_PROTECTED_PORT = 2222
# This isn't the same machine as the protected service, so we use NAT to forward
DEFAULT_TARGET_HOST = "172.20.0.20"
DEFAULT_TARGET_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
KNOCK_SUCCESS_TIMEOUT = 60.0  # how long to keep port open after successful knock


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def initialize_firewall():
    """Set up initial firewall rules to block all traffic except for knock ports."""
    logging.info("Initializing firewall rules")
    # iptables should be installed, see Dockerfile
    subprocess.run(
        ["iptables", "-F"],  # Flush existing rules
        check=True,
    )
    subprocess.run(
        ["iptables", "-P", "INPUT", "DROP"],  # Default policy to DROP
        check=True,
    )
    subprocess.run(
        ["iptables", "-P", "FORWARD", "DROP"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-A", "INPUT", "-m", "conntrack",
            "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-A", "FORWARD", "-m", "conntrack",
            "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=True,
    )
    for port in DEFAULT_KNOCK_SEQUENCE:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-p", "tcp",
                "--dport", str(port), "-j", "ACCEPT"],
            check=True,
        )
    # Also open dummy ports to confuse port scanners
    for port in DEFAULT_DUMMY_PORTS:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-p", "tcp",
                "--dport", str(port), "-j", "ACCEPT"],
            check=True,
        )


def open_protected_port(protected_port, source_ip):
    """Open the protected port for a specific source IP."""
    logging.info("Open firewall for port %s from %s",
                 protected_port, source_ip)
    subprocess.run(
        ["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "-s", source_ip,
            "--dport", str(protected_port), "-j", "DNAT",
            "--to-destination", f"{DEFAULT_TARGET_HOST}:{DEFAULT_TARGET_PORT}"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-I", "FORWARD", "-p", "tcp", "-s", source_ip, "-d",
            DEFAULT_TARGET_HOST, "--dport", str(
                DEFAULT_TARGET_PORT), "-m", "conntrack",
            "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-t", "nat", "-I", "POSTROUTING", "-p", "tcp", "-s", source_ip,
            "-d", DEFAULT_TARGET_HOST, "--dport", str(DEFAULT_TARGET_PORT),
            "-j", "MASQUERADE"],
        check=True,
    )


def close_protected_port(protected_port, source_ip):
    """Close the protected port for a specific source IP."""
    logging.info("Close firewall for port %s from %s",
                 protected_port, source_ip)
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-p", "tcp", "-s", source_ip,
            "-d", DEFAULT_TARGET_HOST, "--dport", str(DEFAULT_TARGET_PORT),
            "-j", "MASQUERADE"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-D", "FORWARD", "-p", "tcp", "-s", source_ip, "-d",
            DEFAULT_TARGET_HOST, "--dport", str(
                DEFAULT_TARGET_PORT), "-m", "conntrack",
            "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"],
        check=True,
    )
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", source_ip,
            "--dport", str(protected_port), "-j", "DNAT",
            "--to-destination", f"{DEFAULT_TARGET_HOST}:{DEFAULT_TARGET_PORT}"],
        check=True,
    )


def close_protected_port_after_timeout(protected_port, source_ip, open_rules):
    """Close the protected port after a timeout."""
    time.sleep(KNOCK_SUCCESS_TIMEOUT)
    close_protected_port(protected_port, source_ip)
    open_rules.discard(source_ip)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    sequence_map = {
        sequence[i]: sequence[i + 1] for i in range(len(sequence) - 1)
    }

    knockers = {
        # source_ip: (current_port, first_knock_time)
    }
    valid_clients = set()
    running = True

    def listener(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", port))
        sock.listen()
        logger.info("Listening on port %s", port)
        while running:
            conn, addr = sock.accept()
            source_ip = addr[0]
            logger.info("Received knock from %s on port %s", source_ip, port)
            now = time.time()

            if source_ip not in knockers:
                if port == sequence[0]:
                    knockers[source_ip] = (port, now)
                    logger.info("Started sequence for %s", source_ip)
            else:
                last_port, first_knock_time = knockers[source_ip]
                if now - first_knock_time > window_seconds:
                    del knockers[source_ip]
                    logger.info("Sequence timed out for %s", source_ip)
                elif port == sequence_map.get(last_port):
                    if port == sequence[-1]:
                        open_protected_port(protected_port, source_ip)
                        logger.info(
                            "Sequence complete for %s, opened protected port", source_ip)
                        valid_clients.add(source_ip)
                        threading.Thread(
                            target=close_protected_port_after_timeout,
                            args=(protected_port, source_ip, valid_clients),
                            daemon=True,
                        ).start()
                        del knockers[source_ip]
                    else:
                        knockers[source_ip] = (port, first_knock_time)
                        logger.info(
                            "Progressed sequence for %s to port %s", source_ip, port)
                else:
                    del knockers[source_ip]
                    logger.info(
                        "Incorrect knock from %s, resetting sequence", source_ip)

    def cleanup_listener():
        while running:
            now = time.time()
            for source_ip in list(knockers):
                _, first_knock_time = knockers[source_ip]
                if now - first_knock_time > window_seconds:
                    del knockers[source_ip]
                    logger.info("Sequence timed out for %s", source_ip)
            time.sleep(1)

    for port in sequence:
        thread = threading.Thread(target=listener, args=(port,), daemon=True)
        thread.start()

    cleanup_thread = threading.Thread(target=cleanup_listener, daemon=True)
    cleanup_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down knock server")
        for source_ip in list(valid_clients):
            close_protected_port(protected_port, source_ip)
        running = False

    cleanup_thread.join()


def setup_dummy_ports(dummy_ports):
    """Set up dummy ports to confuse port scanners."""
    logging.info("Setting up dummy ports to confuse port scanners")

    def dummy_listener(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", int(port)))
        sock.listen()
        while True:
            conn, addr = sock.accept()
            conn.close()
    for port in dummy_ports:
        thread = threading.Thread(
            target=dummy_listener, args=(port,), daemon=True)
        thread.start()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    parser.add_argument(
        "--dummy-ports",
        default=",".join(str(port) for port in DEFAULT_DUMMY_PORTS),
        help="Comma-separated dummy ports to confuse port scanners",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    initialize_firewall()
    setup_dummy_ports(args.dummy_ports.split(","))
    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
