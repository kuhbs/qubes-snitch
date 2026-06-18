#!/usr/bin/env python3
#
# Line-based terminal UI for Qubes Snitch
# The daemon sends one queued question over the Unix socket; this CLI prints it and returns one allow/reject answer

import fcntl
import json
import socket
import sys
import termios
import tty

from qubes_snitch import config
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


def ask(request, config):
    # The prompt shows [a/R]; only a/A allows, and every other key safely rejects
    sys.stdout.write(packet_line(request, config))
    sys.stdout.flush()
    key = read_key()
    action = "allow" if key in ("a", "A") else "reject"
    # Echo the normalized decision so the terminal scrollback shows what the user chose
    sys.stdout.write("a\n" if action == "allow" else "r\n")
    sys.stdout.flush()
    return action


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
    config_data = config.read_config(CONFIG_FILE)
    sys.stdout.write(header_line(config_data))
    sys.stdout.flush()
    while True:
        handle_request(config_data)


if __name__ == "__main__":
    main()
