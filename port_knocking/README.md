## Port Knocking Starter Template

This directory is a starter template for the port knocking portion of the assignment.

### What you need to implement
- Pick a protected service/port (default is 2222).
- Define a knock sequence (e.g., 1234, 5678, 9012).
- Implement a server that listens for knocks and validates the sequence.
- Open the protected port only after a valid sequence.
- Add timing constraints and reset on incorrect sequences.
- Implement a client to send the knock sequence.

### Getting started
1. Implement your server logic in `knock_server.py`.
2. Implement your client logic in `knock_client.py`.
3. Update `demo.sh` to demonstrate your flow.
4. Run from the repo root with `docker compose up port_knocking`.

### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```

## Port Knocking Design
This service exposes a hidden SSH service behind a knock sequence. The knock server listens on a set of TCP ports. A client must connect to them in order within a time window. When the final knock is received, the server temporarily allows traffic from that source IP to reach the protected service and then revokes access.

### Components
- Knock listener: one TCP listener per knock port.
- Sequence tracker: per-source-IP state (current port + first knock timestamp).
- Firewall controller: inserts/removes iptables rules on success.
- Dummy ports: optional listeners to confuse basic scans.

### Network model
The protected SSH service runs in a different container. The knock server uses NAT to forward the protected port on the knock container to the SSH container:
- Incoming to 172.20.0.40:2222 is DNATed to 172.20.0.20:2222.
- A per-source FORWARD rule allows only the successful client IP.
- MASQUERADE is applied so replies are routed back through the knock container.

### Sequence validation
- The server accepts only the configured port order.
- Each client has a single active sequence tracked by IP.
- If the time window expires or a wrong port is hit, the client is forgotten and the sequence must be restarted.

### Timing and cleanup
- On success, rules are inserted for that source IP.
- Rules are removed after a timeout.
- On shutdown, all per-IP rules are removed.

### Typical flow
1. Client knocks in order on the configured ports.
2. Server validates the sequence within the time window.
3. Server inserts DNAT/FORWARD/MASQUERADE rules for the source IP.
4. Client connects to 172.20.0.40:2222 and reaches SSH on 172.20.0.20:2222.
5. After timeout, rules are removed and new connections are blocked. Old connections remain connected, ensuring only new connections will have to repeat the knock.

### Defaults
- Knock sequence: 14687, 21353, 4331, 5678
- Protected port: 2222
- Target SSH host: 172.20.0.20:2222
- Window: 10 seconds
- Success timeout: 60 seconds

