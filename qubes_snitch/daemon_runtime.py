# Runtime wiring for qubes-snitchd
# The executable imports this module; focused modules own source, policy, alert, DNS-cache, and packet logic

import grp
import os
import signal
import socket
import subprocess
import sys
import syslog
import threading
import time

import qubesdb
import yaml
from netfilterqueue import NetfilterQueue

from qubes_snitch import alerts_runtime
from qubes_snitch import dns_cache_runtime
from qubes_snitch import packet_handlers
from qubes_snitch import policy_runtime
from qubes_snitch import sources_runtime
from qubes_snitch import queue
from qubes_snitch.dns import dns_reject_payload
from qubes_snitch.packets import parse_packet
from qubes_snitch.paths import CONFIG_FILE, LOCK_FILE, NFT_FILE, RULES_DIR, RUN_DIR, SOCKET_FILE

# nft table and NFQUEUE numbers are daemon runtime constants; installed paths live in qubes_snitch.paths
NFT_TABLE = "qubes_snitch"
QUEUE_NUM = 50

# notify-send must run as the GUI user, not root, or XFCE/DBus notifications will not appear
NOTIFY_USER = "user"
NOTIFY_DISPLAY = ":0"
NOTIFY_RUNTIME_DIR = "/run/user/1000"
NOTIFY_DBUS = "unix:path=/run/user/1000/bus"

# qrexec gives sys-snitch live dom0 VM names, IPv4 addresses, labels, class, and template
SOURCE_SERVICE = "qubes.SnitchSources"
SOURCE_REFRESH_INTERVAL = 2.0
LAST_SOURCE_REFRESH = 0.0

# QubesDB is the same push signal Qubes' sys-firewall uses when connected IPs or firewall data change
QDB_WATCH_PATHS = ("/connected-ips", "/qubes-firewall/")

# Keep the server socket global so SIGTERM/SIGINT cleanup can close and unlink it
SERVER_SOCKET = None

# YAML on disk is the durable policy; packet callbacks read these in-memory copies for speed
# Restart qubes-snitchd after hand-editing YAML so these copies and nft rules reload together
SOURCES_BY_NAME = {}
SOURCES_BY_IP = {}
SOURCE_LABELS = {}
SOURCE_DISPLAY_BY_IP = {}
RULES = {}
CONFIG = {}
DNS_RESPONSE_CACHE = {}
DNS_QNAME_CACHE = {}

# NFQUEUE callbacks, CLI writes, and QubesDB refreshes share process memory, so locks protect publish points
POLICY_LOCK = threading.Lock()
DNS_CACHE_LOCK = threading.Lock()
LOG_BUCKETS = {}


def context():
    # Runtime helpers receive this module as the mutable daemon state object
    return sys.modules[__name__]


def handle_cli_connection(conn):
    # Delegate the one-question socket protocol to queue.py
    runtime = context()

    def save_rule(request, action):
        # queue.save_pending_decision already holds POLICY_LOCK here, so read the source map directly
        if not policy_runtime.prompt_source_current(runtime, request):
            syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH ignore stale CLI decision after source changed: {request.get('source')}")
            return
        return policy_runtime.append_rule(runtime, request, action)

    def enrich_request(request):
        # DNS/PTR refresh can block briefly, so do it in the CLI thread instead of the NFQUEUE packet callback
        with POLICY_LOCK:
            if not policy_runtime.prompt_source_current(runtime, request):
                return None
        enriched = dns_cache_runtime.enrich_prompt_request(runtime, request)
        with POLICY_LOCK:
            if not policy_runtime.prompt_source_current(runtime, request):
                return None
        return enriched

    def reload_nft():
        return policy_runtime.load_nft(runtime)

    try:
        queue.handle_cli_connection(conn, POLICY_LOCK, save_rule, reload_nft, enrich_request)
    except BaseException as error:
        # A failed YAML save, validation abort, or nft reload leaves prompt handling unsafe, so fail the whole daemon
        alerts_runtime.fatal_security_alert(runtime, ("cli-decision-failed",), f"CLI decision persistence failed REASON={error}")


def cli_server():
    # Run CLI socket handling outside NFQUEUE; if this loop dies, prompts cannot be answered
    runtime = context()
    try:
        while True:
            conn, _ = SERVER_SOCKET.accept()
            handle_cli_connection(conn)
    except BaseException as error:
        alerts_runtime.fatal_security_alert(runtime, ("cli-server-failed",), f"CLI server failed REASON={error}")


def open_socket():
    # The Unix socket is only local to sys-snitch and carries one JSON request plus one text answer per connection
    global SERVER_SOCKET
    SERVER_SOCKET = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        SERVER_SOCKET.bind(str(SOCKET_FILE))
    except OSError as error:
        raise SystemExit(f"cannot bind qubes-snitchd socket: {error}") from error
    os.chown(SOCKET_FILE, 0, grp.getgrnam(NOTIFY_USER).gr_gid)
    SOCKET_FILE.chmod(0o660)
    SERVER_SOCKET.listen(1)


def stop(_signum, _frame):
    # On clean shutdown, remove temporary numbered DispVM policy and the stale socket path
    policy_runtime.cleanup_numbered_dispvm_files(context())
    if SERVER_SOCKET:
        SERVER_SOCKET.close()
    if SOCKET_FILE.exists():
        SOCKET_FILE.unlink()
    raise SystemExit(0)


def setup_run_dir():
    # Runtime directory is root-owned while socket and CLI lock remain group-readable for the GUI user
    run_group = grp.getgrnam(NOTIFY_USER).gr_gid
    RUN_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(RUN_DIR, 0, run_group)
    RUN_DIR.chmod(0o750)
    LOCK_FILE.touch(mode=0o660, exist_ok=True)
    os.chown(LOCK_FILE, 0, run_group)
    LOCK_FILE.chmod(0o660)


def run_queues():
    # All supported decisions happen on the forward queue; DNS replies are not parsed for hints
    runtime = context()

    def handle_packet(packet):
        return packet_handlers.handle_packet(runtime, packet)

    queue = NetfilterQueue()
    queue.bind(QUEUE_NUM, handle_packet)
    queue.run()


def main():
    # systemd ExecStartPre owns fail-closed nft before Python starts, so the daemon only loads real policy
    runtime = context()
    setup_run_dir()
    RULES_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    policy_runtime.load_policy_without_sources(runtime)
    open_socket()
    threading.Thread(target=cli_server, daemon=True).start()
    sources_runtime.refresh_sources_required(runtime)
    threading.Thread(target=lambda: sources_runtime.qubesdb_source_watcher(runtime), daemon=True).start()
    run_queues()
