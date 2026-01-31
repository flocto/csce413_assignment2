#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
""" 

import argparse
import threading
import itertools
import socket
import sys
import queue

import tqdm

DEFAULT_TIMEOUT = 0.05 # seconds

def parse_cidr(cidr):
    """
    Parse CIDR notation and return a list of IP addresses

    Args:
        cidr (str): CIDR notation (e.g., 172.17.0.0/16)
    Returns:
        list: List of IP addresses in the CIDR range
    """
    # lol thanks python https://docs.python.org/3/library/ipaddress.html 
    import ipaddress
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def identify_service(banner):
    """
    Attempt to identify service based on banner
    *Note: Very heuristics based and only a PoC for the assignment*

    Args:
        banner (bytes): Banner data received from the service
    """
    if not banner:
        return "unknown"
    b = banner
    lower = b.lower()
    if b.startswith(b"SSH-"):
        ssh_ver = b.split()[0][4:].decode(errors='ignore')
        return f'SSH {ssh_ver}'
    if len(b) > 4 and b[4] == 0x0A:
        return "MySQL"
    if b"mysql" in lower or b"caching_sha2_password" in lower or b"mysql_native_password" in lower:
        mysql_ver = b.split(b'\n', 1)[1].split(b'\x00', 1)[0].decode(errors='ignore')
        return f'MySQL {mysql_ver}'
    if b.startswith(b"+PONG") or b.startswith(b"-NOAUTH") or b"redis" in lower:
        return "Redis"
    if b.startswith(b"HTTP/") or b"Server:" in b:
        server = [line for line in b.split(b"\r\n") if line.startswith(b"Server:")][0]
        server_info = server.split(b":", 1)[1].strip().decode(errors='ignore')
        return f"HTTP {server_info}"
    if b.startswith(b"220"):
        return "FTP"
    return "unknown"

def scan_port(target, port, timeout=DEFAULT_TIMEOUT, captured_banners=None):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds
        captured_banners (tuple(threading.Lock, dict), optional): Dictionary to store captured banners

    Returns:
        bool: True if port is open, False otherwise
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((target, port)) != 0:
            sock.close()
            return False
    
        if captured_banners is not None:
            banner = b""
            best_banner = b""
            service = "unknown"
            try:
                banner = sock.recv(1024)
            except socket.error:
                banner = b""

            if banner:
                best_banner = banner
                service = identify_service(banner)

            if service == "unknown":
                for probe in (b"HEAD / HTTP/1.0\r\n\r\n", b"PING\r\n", b"USER anonymous\r\n"):
                    try:
                        sock.sendall(probe)
                        banner = sock.recv(1024)
                    except socket.error:
                        banner = b""
                    if banner:
                        best_banner = banner
                        service = identify_service(banner)
                        if service != "unknown":
                            break

            if best_banner:
                with captured_banners[0]:
                    captured_banners[1][target, port] = f"{service}"

        sock.close()
        return True

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def _multi_threaded_scan(target_list, start_port, end_port, threads, verbose):
    """
    Perform multi-threaded port scanning

    Args:
        target_list (list): List of IP addresses or hostnames to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): Number of threads to use
        verbose (bool): Verbose output flag

    Returns:
        list: List of open ports
    """
    open_ports = []
    list_lock = threading.Lock()
    banner_lock = threading.Lock()
    captured_banners = (banner_lock, {})
    update_queue = queue.Queue()
    batch_size = 50

    def worker(target_port_queue, progress):
        pending = 0
        while True:
            target_port = next(target_port_queue, None)
            if target_port is None:
                break
            target, port = target_port
            result = scan_port(target, port, captured_banners=captured_banners)
            if verbose:
                banner = captured_banners[1].get((target, port), b'')
                msg = f"[*] {target}:{port} - {'open' if result else 'closed'} {'| ' + str(banner) if banner else ''}"
                if progress:
                    tqdm.tqdm.write(msg)
                else:
                    print(msg)
            if result:
                with list_lock:
                    open_ports.append((target, port))
            pending += 1
            if pending >= batch_size:
                update_queue.put(pending)
                pending = 0
        if pending:
            update_queue.put(pending)

    def progress_bar(progress):
        while True:
            n = update_queue.get()
            if n is None:
                break
            progress.update(n)

    target_port_queue = itertools.product(target_list, range(start_port, end_port + 1))
    thread_list = []
    total = len(target_list) * (end_port - start_port + 1)

    with tqdm.tqdm(total=total) as progress:
        try:
            p = threading.Thread(target=progress_bar, args=(progress,))
            p.start()
            for _ in range(threads):
                t = threading.Thread(target=worker, args=(target_port_queue, progress))
                t.start()
                thread_list.append(t)

            for t in thread_list:
                t.join()
            update_queue.put(None)
            p.join()
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            sys.exit(1)

    return open_ports, captured_banners

def scan_range(target, start_port, end_port, threads=1, verbose=False):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    target_list = parse_cidr(target)
    if not target_list:
        target_list = [target]

    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    if threads > 1:
        open_ports, captured_banners = _multi_threaded_scan(target_list, start_port, end_port, threads, verbose)
    else:
        captured_banners = (threading.Lock(), {})
        target_port_list = list(itertools.product(target_list, range(start_port, end_port + 1)))
        for target, port in tqdm.tqdm(target_port_list):
                result = scan_port(target, port, captured_banners=captured_banners)
                if verbose:
                    banner = captured_banners[1].get((target, port), b'')
                    print(f"[*] {target}:{port} - {'open' if result else 'closed'} {'| ' + str(banner) if banner else ''}")
                if result:
                    open_ports.append((target, port))

    return open_ports, captured_banners[1]

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Port Scanner Module")
    parser.add_argument("--target", type=str, help="Target IP address or hostname to scan", required=True)
    parser.add_argument("--ports", type=str, help="Port range to scan (e.g., 1-1024)", required=True)
    parser.add_argument("--threads", type=int, default=1, help="Number of threads to use (default: 1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    target = args.target
    port_range = args.ports
    threads = args.threads
    verbose = args.verbose
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print("Invalid port range. Use format: start-end (e.g., 1-1024, min 1, max 65535)")
        sys.exit(1)

    print(f"[*] Starting port scan on {target}")

    open_ports, captured_banners = scan_range(target, start_port, end_port, threads, verbose)
    open_ports.sort()

    print(f"\n[+] Scan complete!")
    max_len = max((len(f"{t}:{p}") for t, p in open_ports), default=0)
    print(f"[+] Found {len(open_ports)} open ports:")
    print("-------------------------------------")
    print(f"{'Address':<{max_len + 4}} - Status | Banner")
    print("-------------------------------------")
    for target, port in open_ports:
        banner = captured_banners.get((target, port), b'')
        addr = f"{target}:{port}"
        print(f"    {addr:>{max_len}} - open   {'| ' + str(banner) if banner else '| unknown'}")


if __name__ == "__main__":
    main()
