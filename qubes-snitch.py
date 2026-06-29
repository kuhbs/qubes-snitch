#!/usr/bin/env python3
#
# Line-based terminal UI for Qubes Snitch
# The daemon sends one queued question over the Unix socket; this CLI prints it and returns one allow/reject answer

import fcntl
import ipaddress
import json
import socket
import sys
import termios
import tty

from qubes_snitch import config as snitch_config
from qubes_snitch.paths import CONFIG_FILE, LOCK_FILE, SOCKET_FILE
from qubes_snitch.ui import header_line, packet_line


def read_key():
    # Read exactly one keypress so accepting a connection is a fast single-key action
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        key = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return key


def resolve_hostname_ips(hostname):
    # Preview the exact IPv4 set before the user chooses hostname-backed policy
    import dns.resolver

    answers = dns.resolver.resolve(hostname, "A", lifetime=3.0)
    ips = []
    for answer in answers:
        address = ipaddress.ip_address(answer.to_text())
        if address.version == 4:
            ips.append(str(address))
    return sorted(set(ips), key=ipaddress.ip_address)


def add_hostname_choices(request):
    # Only multi-IP A records get hostname policy choices; single-IP rows stay compact a/r prompts
    host = request.get("host")
    if not isinstance(host, str) or not host.startswith("A "):
        return
    try:
        hostname = snitch_config.validate_dest_dns_name("prompt", host[2:])
        ips = resolve_hostname_ips(hostname)
    except Exception:
        return
    if len(ips) > 1 and request["dst"] in ips:
        request["_resolved_dests"] = ips


def ask(request, config):
    # Only displayed keys are decisions; accidental Enter or other keys redraw the prompt
    request = dict(request)
    add_hostname_choices(request)
    while True:
        sys.stdout.write(packet_line(request, config))
        sys.stdout.flush()
        key = read_key()
        if key == "a":
            sys.stdout.write("a\n")
            sys.stdout.flush()
            return "allow"
        if key == "r":
            sys.stdout.write("r\n")
            sys.stdout.flush()
            return "reject"
        if key == "A" and "_resolved_dests" in request:
            sys.stdout.write("A\n")
            sys.stdout.flush()
            return "allow-dns"
        if key == "R" and "_resolved_dests" in request:
            sys.stdout.write("R\n")
            sys.stdout.flush()
            return "reject-dns"
        sys.stdout.write("\n")
        sys.stdout.flush()


def acquire_cli_lock():
    # Allow only one interactive CLI because two terminals would race for queued questions
    try:
        LOCK_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    except PermissionError:
        # systemd creates /run/qubes-snitch for the daemon; a normal user cannot create it when the daemon is stopped
        raise SystemExit("qubes-snitchd is not running")
    handle = LOCK_FILE.open("w", encoding="utf-8")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise SystemExit("another qubes-snitch is already running")
    return handle


def connect_socket():
    # Fail with a readable message when the daemon socket is missing or stale
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(SOCKET_FILE))
        return client
    except FileNotFoundError:
        client.close()
        raise SystemExit("qubes-snitchd is not running")
    except ConnectionRefusedError:
        client.close()
        raise SystemExit("qubes-snitchd socket exists, but the daemon is not accepting connections")


def handle_request(config):
    # Handle one queued question per socket connection; reconnecting avoids stateful CLI protocol code
    with connect_socket() as client:
        try:
            line = client.makefile("r", encoding="utf-8").readline()
        except ConnectionResetError:
            # Treat a reset as harmless because the daemon can restart or close stale sockets while the CLI waits
            return
        if not line:
            return
        request = json.loads(line)
        client.sendall((ask(request, config) + "\n").encode("utf-8"))


def main():
    # Read config once at startup; restart the CLI if the user changes terminal theme settings
    lock_handle = acquire_cli_lock()
    config_data = snitch_config.read_config(CONFIG_FILE)
    sys.stdout.write(header_line(config_data))
    sys.stdout.flush()
    while True:
        handle_request(config_data)


if __name__ == "__main__":
    main()
