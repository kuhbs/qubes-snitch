# Packet field extraction for Qubes Snitch
# This is not a full firewall parser; it extracts only fields needed for prompts and policy keys

import ipaddress
import socket
import struct


def normalize_port(value, proto):
    # Normalize user YAML ports to a simple string: any, one number, one range, or one /etc/services name
    if isinstance(value, bool):
        raise ValueError("port must be a number, range, service name, or any")
    if value == "any":
        return "any"
    if isinstance(value, int) or str(value).isdigit():
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError("port out of range")
        return str(port)
    text = str(value)
    if proto not in ("tcp", "udp"):
        raise ValueError("service names require tcp or udp")
    try:
        return str(socket.getservbyname(text, proto))
    except OSError:
        pass
    if "-" in text and all(part.isdigit() for part in text.split("-", 1)):
        start, end = [int(part) for part in text.split("-", 1)]
        if not 1 <= start <= end <= 65535:
            raise ValueError("port range out of range")
        return f"{start}-{end}"
    raise ValueError("unknown service name or port range")


def parse_packet(payload):
    # NFQUEUE gives raw IPv4 packets; failed extraction becomes malformed traffic instead of a user prompt
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    malformed = None
    if version != 4:
        return None
    # IPv4 IHL is the low nibble in 32-bit words, so multiply by four to get bytes
    header_len = (payload[0] & 15) * 4
    total_length = struct.unpack("!H", payload[2:4])[0]
    proto_num = payload[9]
    # IPv4 flags and fragment offset share this 16-bit field
    fragment_field = struct.unpack("!H", payload[6:8])[0]
    src = socket.inet_ntop(socket.AF_INET, payload[12:16])
    dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
    if header_len < 20 or header_len > len(payload):
        malformed = "bad ipv4 header length"
    elif total_length != len(payload):
        malformed = "ipv4 total length mismatch"
    elif fragment_field & 0x8000:
        # The reserved IPv4 flag is not valid traffic, so never turn it into user policy
        malformed = "ipv4 reserved flag set"
    elif fragment_field & 0x3fff:
        # Snitch does not reassemble IPv4 fragments, so never treat fragment bytes as TCP/UDP ports
        malformed = "ipv4 fragments unsupported"
    proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(proto_num, str(proto_num))
    request = {"src": src, "dst": dst, "proto": proto, "sport": None, "dport": None, "body": b""}
    if proto not in ("icmp", "tcp", "udp") and not malformed:
        malformed = "unsupported ipv4 protocol"
    if malformed:
        request["malformed"] = malformed
        return request
    if proto == "icmp" and len(payload) < header_len + 4:
        # ICMP policy is protocol-wide, so never prompt from bytes that do not even contain type/code/checksum
        request["malformed"] = "missing icmp header"
        return request
    if proto in ("tcp", "udp"):
        if len(payload) < header_len + 4:
            request["malformed"] = "missing transport ports"
            return request
        if proto == "udp" and len(payload) < header_len + 8:
            request["malformed"] = "missing udp header"
            return request
        request["sport"], request["dport"] = struct.unpack("!HH", payload[header_len:header_len + 4])
        if request["sport"] == 0:
            request["malformed"] = "tcp/udp source port 0"
            return request
        if request["dport"] == 0:
            request["malformed"] = "tcp/udp destination port 0"
            return request
        if proto == "tcp":
            if len(payload) < header_len + 20:
                request["malformed"] = "missing tcp header"
                return request
            # TCP data offset is the high nibble in 32-bit words, so multiply by four to get bytes
            tcp_header_len = (payload[header_len + 12] >> 4) * 4
            if tcp_header_len < 20 or header_len + tcp_header_len > total_length:
                request["malformed"] = "bad tcp data offset"
                return request
        if proto == "udp":
            # UDP length covers the UDP header plus body and must line up with the IPv4 total length
            udp_length = struct.unpack("!H", payload[header_len + 4:header_len + 6])[0]
            if udp_length < 8 or header_len + udp_length != total_length:
                request["malformed"] = "bad udp length"
                return request
            request["body"] = payload[header_len + 8:header_len + udp_length]
    return request


def request_family(request):
    # Snitch supports IPv4 only; reject accidental non-IPv4 before it reaches rule matching
    if ipaddress.ip_address(request["dst"]).version != 4:
        raise ValueError("non-IPv4 is unsupported")
    return "rules4"


def request_port(request):
    # Protocols without TCP/UDP ports use port:any in prompts and YAML rules
    port = request["dport"] or "any"
    return str(port)


def request_without_body(request):
    # Remove raw body bytes before JSON serialization; the CLI only displays semantic fields
    prompt_request = dict(request)
    if "body" in prompt_request:
        del prompt_request["body"]
    return prompt_request
