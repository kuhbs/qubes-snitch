# Terminal prompt formatting for Qubes Snitch
# The daemon sends semantic request fields; this module turns them into one readable terminal line
import socket

from qubes_snitch.display import safe_text


# Column order is stable so users can scan repeated prompts quickly: queue count, source, target, DNS, service, action
# A visible gap is added between columns because long domains can exceed their nominal width
DEFAULT_PROMPT_COLUMN_WIDTHS = {
    "queue": 10,
    "source": 18,
    "target": 25,
    "dns": 42,
    "service": 22,
}
COLUMN_GAP = " "
RESET = "\033[0m"
BOLD = "\033[1m"
DEFAULT_FOREGROUND = "\033[39m"
UNKNOWN_SOURCE_COLOR = "\033[1;91m"
DARK_NET_KIND_COLOR = "\033[96m"
LIGHT_NET_KIND_COLOR = "\033[34m"
ENCRYPTED_PROTOCOL_COLOR = "\033[92m"
UNENCRYPTED_PROTOCOL_COLOR = "\033[93m"
UNLISTED_PROTOCOL_COLOR = "\033[91m"
QUBES_INTERNAL_DNS = {
    "10.139.1.1": "qubes.dns-1.internal",
    "10.139.1.2": "qubes.dns-2.internal",
}

# Qubes label colors need separate palettes for dark and light terminal backgrounds
DARK_LABEL_COLORS = {
    "red": "\033[91m",
    "orange": "\033[93m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "gray": "\033[97m",
    "blue": "\033[94m",
    "purple": "\033[95m",
    "black": "\033[97m",
}
LIGHT_LABEL_COLORS = {
    "red": "\033[31m",
    "orange": "\033[33m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "gray": "\033[90m",
    "blue": "\033[34m",
    "purple": "\033[35m",
    "black": "\033[30m",
}


def prompt_widths(config=None):
    # CLI tests and old callers can omit config; real runtime uses config.yml values
    if not config:
        return DEFAULT_PROMPT_COLUMN_WIDTHS
    return config.get("prompt_column_widths", DEFAULT_PROMPT_COLUMN_WIDTHS)


def label_color(theme, label):
    # Missing source labels are uncolored because dom0 did not provide a trusted Qubes label
    if label == "unknown":
        return DEFAULT_FOREGROUND
    colors = DARK_LABEL_COLORS if theme == "dark" else LIGHT_LABEL_COLORS
    if label not in colors:
        raise SystemExit(f"unknown Qubes label for source color: {label}")
    return colors[label]


def source_label(request):
    # Known sources get color from their Qubes label; missing labels stay plain text
    if "source_label" not in request:
        return "unknown"
    return request["source_label"]


def colored_source(request, theme, widths):
    # Reset color right after the source column so destinations and actions do not inherit label colors
    source = f"{safe_text(request.get('display_source', request['source'])):<{widths['source']}}"
    if request.get("source_unknown"):
        return f"{UNKNOWN_SOURCE_COLOR}{source}{RESET}"
    return f"{label_color(theme, source_label(request))}{source}{RESET}"


def host_text(request):
    # Show no PTR instead of a blank field so users know no readable destination name is available
    return safe_text(request.get("host") or "no PTR")


def color_cell(text, width, color):
    # Pad outside the ANSI sequence so terminal columns stay aligned after the color reset
    text = safe_text(text)
    return f"{color}{text}{RESET}{' ' * max(width - len(text), 0)}"


def dns_kind_color(config):
    # DNS policy questions are visually distinct from normal service coloring
    return DARK_NET_KIND_COLOR if config["theme"] == "dark" else LIGHT_NET_KIND_COLOR


def protocol_color(config, proto, port):
    # ICMP has no port and remains red because it is not a listed proto/port service
    if proto == "icmp":
        return UNLISTED_PROTOCOL_COLOR
    if port == "-":
        return DEFAULT_FOREGROUND
    key = (proto, str(port))
    colors = config["prompt_protocol_colors"]
    if key in colors["encrypted"]:
        return ENCRYPTED_PROTOCOL_COLOR
    if key in colors["unencrypted"]:
        return UNENCRYPTED_PROTOCOL_COLOR
    return UNLISTED_PROTOCOL_COLOR


def service_name(proto, port):
    # /etc/services is the source of truth so users can add local names for custom ports
    try:
        return socket.getservbyport(int(port), proto)
    except OSError:
        return None


def service_label(proto, port):
    # ICMP has no TCP/UDP port, so show the protocol instead of a blank service
    if proto == "icmp":
        return "icmp"
    # Show the service name when /etc/services knows it, otherwise show the raw proto/port pair
    pair = f"{port}/{proto}"
    name = service_name(proto, port)
    if name:
        return f"{name} {pair}"
    return pair


def is_dns_transport(request):
    # Resolver transport is a normal UDP flow, but its color is a DNS-path warning/signal
    return request.get("proto") == "udp" and str(request.get("dport")) == "53"


def resolver_dns_name(request):
    # Qubes internal resolvers are stable names; other resolver names keep their A/PTR trust prefix
    if request["dst"] in QUBES_INTERNAL_DNS:
        return QUBES_INTERNAL_DNS[request["dst"]]
    return host_text(request)


def dns_traffic_color(config, request):
    # Qubes internal DNS is expected; direct DNS to any other resolver bypasses that path
    if request["dst"] in QUBES_INTERNAL_DNS:
        return dns_kind_color(config)
    return UNLISTED_PROTOCOL_COLOR


def dns_text(request):
    # Qubes internal DNS has fixed names, so show them even when no PTR exists
    if request["dst"] in QUBES_INTERNAL_DNS:
        return QUBES_INTERNAL_DNS[request["dst"]]
    # A-cache names are stronger than PTR; keep the prefix visible so trust level is obvious
    return host_text(request)


def dns_color(config, request):
    # Qubes internal DNS names are trusted local resolver identities, not missing-PTR failures
    if request["dst"] in QUBES_INTERNAL_DNS:
        return dns_kind_color(config)
    # Color only the name-quality cell for normal IP traffic
    host = request.get("host")
    if not host:
        return UNLISTED_PROTOCOL_COLOR
    if host.startswith("A "):
        return ENCRYPTED_PROTOCOL_COLOR
    if host.startswith("PTR "):
        return UNENCRYPTED_PROTOCOL_COLOR
    return DEFAULT_FOREGROUND


def prompt_fields(config, request):
    # DNS rows are semantic DNS questions, not fake proto/port services
    if request.get("kind") == "dns":
        color = dns_traffic_color(config, request)
        return (request["dst"], request["qname"], f"DNS {request['qtype']}", color, color, color)
    if is_dns_transport(request):
        color = dns_traffic_color(config, request)
        return (request["dst"], resolver_dns_name(request), service_label(request["proto"], request["dport"]), color, color, color)
    port = str(request.get("dport") or "-")
    return (
        request["dst"],
        dns_text(request),
        service_label(request["proto"], port),
        DEFAULT_FOREGROUND,
        dns_color(config, request),
        protocol_color(config, request["proto"], port),
    )


def service_width(widths, target, dns, service):
    # Long target/DNS cells borrow padding from SERVICE so ACTION stays aligned when possible
    target_overflow = max(len(target) - widths["target"], 0)
    dns_overflow = max(len(dns) - widths["dns"], 0)
    return max(widths["service"] - target_overflow - dns_overflow, len(service))


def header_line(config=None):
    # Bold makes the table header easier to scan without assigning it a semantic color
    widths = prompt_widths(config)
    header = (
        f"{'Q':<{widths['queue']}}{COLUMN_GAP}"
        f"{'SOURCE':<{widths['source']}}{COLUMN_GAP}"
        f"{'TARGET':<{widths['target']}}{COLUMN_GAP}"
        f"{'DNS':<{widths['dns']}}{COLUMN_GAP}"
        f"{'SERVICE':<{widths['service']}}{COLUMN_GAP}"
        "ACTION"
    )
    return f"{BOLD}{header}{RESET}\n"


def packet_line(request, config):
    # Fixed-width columns keep the terminal readable while the final [a/R] shows the only accepted action key
    widths = prompt_widths(config)
    target, dns, service, target_color, dns_cell_color, service_color = prompt_fields(config, request)
    remaining = f"{request.get('remaining', 0) + 1:<{widths['queue']}}"
    rendered_service_width = service_width(widths, target, dns, service)
    return (
        f"{remaining}{COLUMN_GAP}"
        f"{colored_source(request, config['theme'], widths)}{COLUMN_GAP}"
        f"{color_cell(target, widths['target'], target_color)}{COLUMN_GAP}"
        f"{color_cell(dns, widths['dns'], dns_cell_color)}{COLUMN_GAP}"
        f"{color_cell(service, rendered_service_width, service_color)}{COLUMN_GAP}"
        "[a/R] "
    )
