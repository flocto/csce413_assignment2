## SSH Honeypot Design Plan

### Goals
- Emulate a realistic SSH service with believable banners and timing.
- Capture authentication attempts, session metadata, and attacker commands.
- Persist events to JSONL in logs/ alongside HTTP events.

### Network and Protocol
- Listen on port 22 inside the container, map host port 2222.
- Present configurable SSH banner (e.g., OpenSSH_8.2p1 Ubuntu-4ubuntu0.5).
- Implement minimal SSH handshake flow to the point of auth prompts.

### Authentication Simulation
- Support password auth prompts and log username/password pairs.
- Allow “soft acceptance” for any credentials to observe post-auth commands.
- Optional rate hints (delays after failed auth) to mimic real servers.

### Session Emulation
- Provide a fake shell prompt and basic command echoing.
- Implement a minimal virtual filesystem tree (/etc, /var, /home, /tmp).
- Common commands to simulate: ls, pwd, whoami, cat, uname, id, ps.
- Log each command with timestamp, session id, and output length.

### Detection and Tagging
- Tag known brute-force patterns (many auth attempts, common usernames).
- Tag use of known exploit probes (e.g., "wget", "curl", "nc", "bash -i").
- Track per-source IP counters for attempts and sessions.

### Logging Schema (JSONL)
- connect: src_ip, src_port, proto=ssh
- auth: username, password, success
- session: session_id, start/end
- command: session_id, command, tag

### Implementation Approach
- Use a lightweight SSH server library or a minimal custom parser.
- Keep the SSH module separate (e.g., ssh_honeypot.py) and plug into main.
- Share the same logger helper for consistent JSONL output.
