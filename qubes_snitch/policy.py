# Policy matching and in-memory rule updates for Qubes Snitch
# The daemon owns files and nft reloads; this module decides what a rule means

import ipaddress

from qubes_snitch.dns import dns_rule_matches
from qubes_snitch.packets import normalize_port, request_family, request_port


def port_matches(request, rule):
    # Convert ports before comparing so service names and numeric ranges match real packet numbers
    port = normalize_port(rule["port"], request["proto"])
    if port == "any":
        return True
    request_port_value = request_port(request)
    if request_port_value == "any":
        return False
    if "-" in port:
        start, end = [int(part) for part in port.split("-", 1)]
        return start <= int(request_port_value) <= end
    return str(request_port_value) == port


def flow_rule_matches(request, rule):
    # Slow scan supports CIDR and range rules that cannot be represented as one exact dictionary key
    if str(rule["proto"]) != request["proto"]:
        return False
    if rule["dest"] != "any" and ipaddress.ip_address(request["dst"]) not in ipaddress.ip_network(str(rule["dest"]), strict=False):
        return False
    return port_matches(request, rule)

def matching_action(request, rules):
    # YAML files store ordered lists; first matching rule wins exactly like rendered nft rules
    if request.get("kind") == "dns":
        for rule in rules[request["source"]]["dns"]:
            if dns_rule_matches(request, rule):
                return rule["action"]
        return None
    for rule in rules[request["source"]]["ip"]:
        if flow_rule_matches(request, rule):
            return rule["action"]
    return None


def append_dns_rule(request, action, data, rules):
    # DNS rules are keyed by source, lowercased qname, and qtype, not by resolver IP
    rule = {"qname": request["qname"], "qtype": request["qtype"], "action": action}
    data["dns"].append(rule)
    if request["source"] not in rules:
        rules[request["source"]] = {"ip": [], "dns": []}
    rules[request["source"]]["dns"].append(rule)


def append_flow_rule(request, action, data, rules):
    # Flow rules save the exact destination/protocol/port observed in the prompt
    if request["proto"] in ("tcp", "udp") and not request["dport"]:
        # Prompted TCP/UDP rules require a real destination port so malformed port 0 cannot become an any-port rule
        raise SystemExit(f"refusing to persist malformed {request['proto']} flow without destination port")
    family_rules = request_family(request)
    rule = {
        "ptr": request["host"] or "no PTR",
        "dest": request["dst"],
        "proto": request["proto"],
        "port": str(request_port(request)),
        "action": action,
    }
    data[family_rules].append(rule)
    if request["source"] not in rules:
        # New sources get the same empty in-memory shape as an empty rule file on disk
        rules[request["source"]] = {"ip": [], "dns": []}
    rules[request["source"]]["ip"].append(rule)
