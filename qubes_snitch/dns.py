# DNS parsing and synthetic reject answers for Qubes Snitch
# Resolver transport is normal UDP/53 traffic; domain policy is a separate qname/qtype decision

import ipaddress
import re
import socket
import struct

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype


# Normal live DNS names need at least two labels and each label must start/end with a letter or digit
LIVE_DNS_QNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
# SRV owner names are the one live form that may start with _service._proto before the normal suffix
LIVE_DNS_SRV_QNAME_RE = re.compile(r"^_[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\._[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

MAX_LIVE_DNS_BODY_BYTES = 1232

SUPPORTED_DNS_QTYPES = {
    "A",
    "CNAME",
    "MX",
    "TXT",
    "SRV",
    "PTR",
    "CAA",
    "NS",
    "SOA",
    "HTTPS",
    "SVCB",
    "NAPTR",
    "DS",
    "DNSKEY",
    "RRSIG",
    "NSEC",
    "NSEC3",
}


def dns_qname_is_ipv6_reverse(qname):
    # ip6.arpa names are IPv6 reverse-DNS policy, and Snitch intentionally has no IPv6 policy surface
    return qname == "ip6.arpa" or qname.endswith(".ip6.arpa")


def normalize_dns_name(name):
    # DNS names are case-insensitive, so store lowercase names without the trailing root dot
    return str(name).rstrip(".").lower()


def dns_qtype_text(rdtype):
    # dnspython converts query type numbers to stable names like A and MX for YAML rules
    return dns.rdatatype.to_text(rdtype).upper()


def dns_rule_matches(request, rule):
    # Wildcards are suffix rules: *.example.com matches a.example.com but not the bare apex
    if request["qtype"] != str(rule["qtype"]).upper():
        return False
    qname = request["qname"]
    rule_name = str(rule["qname"]).lower()
    if rule_name.startswith("*."):
        suffix = rule_name[2:]
        return qname.endswith("." + suffix) and qname != suffix
    return qname == rule_name


def inet_checksum(data):
    # Internet checksums add 16-bit words; odd-length buffers are padded with one zero byte for calculation
    if len(data) % 2:
        data += b"\0"
    # Sum 16-bit network-order words, then fold carries back into the low 16 bits
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def udp_checksum(src, dst, udp_packet):
    # UDP checksum uses the IPv4 pseudo-header
    src_ip = ipaddress.ip_address(src)
    dst_ip = ipaddress.ip_address(dst)
    if src_ip.version != 4 or dst_ip.version != 4:
        raise ValueError("non-IPv4 is unsupported")
    pseudo = src_ip.packed + dst_ip.packed + struct.pack("!BBH", 0, socket.IPPROTO_UDP, len(udp_packet))
    checksum = inet_checksum(pseudo + udp_packet)
    # A computed UDP checksum of zero is transmitted as all ones in IPv4 UDP
    return checksum or 0xffff


def dns_reject_payload(payload, request):
    # Rejected domains get DNS REFUSED so apps fail fast without being redirected to localhost
    query = dns.message.from_wire(request["body"])
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.REFUSED)
    wire = response.to_wire()
    udp_length = 8 + len(wire)
    # Reverse UDP ports because this packet travels from resolver IP back to the client VM
    udp_without_checksum = struct.pack("!HHHH", request["dport"], request["sport"], udp_length, 0) + wire
    checksum = udp_checksum(request["dst"], request["src"], udp_without_checksum)
    udp_packet = struct.pack("!HHHH", request["dport"], request["sport"], udp_length, checksum) + wire
    src_ip = ipaddress.ip_address(request["dst"])
    dst_ip = ipaddress.ip_address(request["src"])
    if src_ip.version != 4 or dst_ip.version != 4:
        raise ValueError("non-IPv4 is unsupported")
    total_length = 20 + len(udp_packet)
    query_id = 0
    reply_flags = 0
    if len(payload) >= 8:
        query_id = struct.unpack("!H", payload[4:6])[0]
        reply_flags = struct.unpack("!H", payload[6:8])[0] & 0x4000
    # Build a fresh IPv4 header with the query ID and DF bit so clients see a normal-looking UDP reply
    header_without_checksum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, query_id, reply_flags, 64, socket.IPPROTO_UDP, 0, src_ip.packed, dst_ip.packed)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, query_id, reply_flags, 64, socket.IPPROTO_UDP, inet_checksum(header_without_checksum), src_ip.packed, dst_ip.packed)
    return header + udp_packet


def live_dns_qname_supported(qname, qtype):
    # Live VM queries are limited to common ASCII names; SRV alone may use _service._proto owner names
    labels = qname.split(".")
    if dns_qname_is_ipv6_reverse(qname) or len(qname) > 253 or any(len(label) > 63 or label.startswith("xn--") for label in labels):
        return False
    if qtype == "SRV":
        return bool(LIVE_DNS_SRV_QNAME_RE.fullmatch(qname))
    return bool(LIVE_DNS_QNAME_RE.fullmatch(qname))


def unsupported_dns(request, reason, question=None):
    # Unsupported DNS is refused without prompt or YAML, so weird packets never enter policy
    request["kind"] = "dns-error"
    request["dns_error"] = reason
    if question is not None:
        request["qname"] = normalize_dns_name(question.name)
        request["qtype"] = dns_qtype_text(question.rdtype)
    return True


def add_dns_query_fields(request):
    # UDP/53 domain policy only accepts a small whitelist of normal one-question IN-class QUERY packets
    if request["proto"] != "udp" or request["dport"] != 53:
        return False
    if not request["body"]:
        return unsupported_dns(request, "empty-body")
    if len(request["body"]) > MAX_LIVE_DNS_BODY_BYTES:
        return unsupported_dns(request, "oversize-body")
    try:
        message = dns.message.from_wire(request["body"])
    except dns.exception.DNSException:
        return unsupported_dns(request, "parse-failed")
    flags = getattr(message, "flags", 0)
    if flags & dns.flags.QR:
        return unsupported_dns(request, "not-client-query")
    # Normal client queries may set RD; response-only/reserved bits and query RCODE are not promptable policy
    if flags & 0x000f:
        return unsupported_dns(request, "non-query-rcode")
    if getattr(message, "opcode", lambda: 0)() != 0:
        return unsupported_dns(request, "non-query-opcode")
    # Mask out already-rejected bits, then allow normal client flags RD/AD/CD and the opcode/rcode bit fields
    allowed_query_flags = dns.flags.QR | 0x7800 | dns.flags.RD | dns.flags.AD | dns.flags.CD | 0x000f
    if flags & ~allowed_query_flags:
        return unsupported_dns(request, "non-query-flags")
    if getattr(message, "answer", []) or getattr(message, "authority", []) or getattr(message, "additional", []):
        return unsupported_dns(request, "unexpected-sections")
    if len(message.question) != 1:
        request["kind"] = "dns-error"
        request["dns_error"] = "multi-question" if message.question else "no-question"
        return True
    question = message.question[0]
    qtype = dns_qtype_text(question.rdtype)
    qclass = dns.rdataclass.to_text(question.rdclass).upper()
    # EDNS version lives in the OPT pseudo-record, so attach the question before refusing it for clean logging/replies
    if getattr(message, "edns", -1) not in (-1, 0):
        return unsupported_dns(request, "unsupported-edns-version", question)
    # EDNS extended RCODEs are error/response semantics and must not become normal qname/qtype policy prompts
    if getattr(message, "rcode", lambda: 0)() != 0:
        return unsupported_dns(request, "non-query-rcode", question)
    # EDNS DO is a normal DNSSEC client flag; other EDNS Z flags are reserved and rejected before policy
    if getattr(message, "ednsflags", 0) & ~0x8000:
        return unsupported_dns(request, "unsupported-edns-flags", question)
    if qclass != "IN":
        return unsupported_dns(request, "unsupported-qclass", question)
    if qtype == "AAAA":
        return unsupported_dns(request, "unsupported-aaaa", question)
    if qtype not in SUPPORTED_DNS_QTYPES:
        return unsupported_dns(request, "unsupported-qtype", question)
    qname = normalize_dns_name(question.name)
    if not live_dns_qname_supported(qname, qtype):
        return unsupported_dns(request, "unsupported-qname", question)
    request["kind"] = "dns"
    request["qname"] = qname
    request["qtype"] = qtype
    return True
