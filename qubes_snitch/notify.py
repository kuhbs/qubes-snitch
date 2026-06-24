# Desktop notification helpers for Qubes Snitch
# The daemon decides when to notify; this module formats popup text and runs notify-send

import subprocess

from qubes_snitch.display import safe_text


SNITCH_ICON = "/usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg"


def request_text(request):
    # Immediate queue notifications use packet-known fields; CLI still shows DNS/PTR-enriched detail later
    source = safe_text(request.get("display_source", request["source"]))
    if request.get("kind") == "dns":
        return f"{source} DNS {safe_text(request['qtype'])} {safe_text(request['qname'])}"
    proto = request["proto"] if request.get("dport") is None else f"{request['proto']}/{request['dport']}"
    return f"{source} -> {safe_text(request['dst'])} {safe_text(proto)}"


def alert_notify(request, config, user, display, runtime_dir, dbus):
    # The daemon is root, but notify-send must run as the logged-in GUI user to reach XFCE notifications
    if not config["notify_send"]:
        return
    subprocess.run([
        "runuser", "-u", user, "--",
        "env", f"DISPLAY={display}", f"XDG_RUNTIME_DIR={runtime_dir}", f"DBUS_SESSION_BUS_ADDRESS={dbus}",
        # Use the installed Snitch SVG directly so notify-send does not depend on icon-theme cache freshness
        "notify-send", f"--icon={SNITCH_ICON}", f"--expire-time={config['notify_send_timeout']}", "QUBES-SNITCH", request_text(request),
    ], check=True, timeout=1)


def security_notify(message, config, user, display, runtime_dir, dbus):
    # Security notifications ignore notify_send because security rejects must stay visible even when prompt popups are disabled
    subprocess.run([
        "runuser", "-u", user, "--",
        "env", f"DISPLAY={display}", f"XDG_RUNTIME_DIR={runtime_dir}", f"DBUS_SESSION_BUS_ADDRESS={dbus}",
        # Security popups use the same icon so urgent daemon failures are visually tied to Snitch
        "notify-send", f"--icon={SNITCH_ICON}", "-u", "critical", "--expire-time=0", "QUBES-SNITCH SECURITY", safe_text(message, limit=300),
    ], check=True, timeout=1)
