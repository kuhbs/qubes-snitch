# Policy matching and in-memory rule updates for Qubes Snitch
# The daemon owns files and nft reloads; this module decides what a rule means

import ipaddress

from qubes_snitch import config
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
    # Slow scan supports CIDR and hostname-backed rules that cannot be exact dictionary keys
    if str(rule["proto"]) != request["proto"]:
        return False
    request_ip = ipaddress.ip_address(request["dst"])
    if "dest_dns" in rule:
        if request["dst"] not in rule["_resolved_dests"]:
            return False
    elif rule["dest"] != "any" and request_ip not in ipaddress.ip_network(str(rule["dest"]), strict=False):
        return False
    return port_matches(request, rule)

def matching_action(request, rules):
    # A numbered DispVM can disappear after packet source lookup but before this policy read
    # Treat a vanished source as no saved rule, which keeps the packet on the reject/prompt path
    source_rules = rules.get(request["source"])
    if source_rules is None:
        return None

    # YAML files store ordered lists; first matching rule wins exactly like rendered nft rules
    if request.get("kind") == "dns":
        for rule in source_rules["dns"]:
            if dns_rule_matches(request, rule):
                return rule["action"]
        return None
    for rule in source_rules["ip"]:
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
    # Flow rules normally save the exact destination observed in the prompt
    if request["proto"] in ("tcp", "udp") and not request["dport"]:
        # Prompted TCP/UDP rules require a real destination port so malformed port 0 cannot become an any-port rule
        raise SystemExit(f"refusing to persist malformed {request['proto']} flow without destination port")
    family_rules = request_family(request)
    host = request.get("host")
    hostname_action = action in ("allow-dns", "reject-dns")
    rule = {
        "ptr": host[2:] if hostname_action and isinstance(host, str) and host.startswith("A ") else host or "no PTR",
        "proto": request["proto"],
        "port": str(request_port(request)),
        "action": {"allow-dns": "allow", "reject-dns": "reject"}.get(action, action),
    }
    if hostname_action:
        # Hostname-backed rules come only from trusted A-cache prompt text, never PTR/no-PTR labels
        if not isinstance(host, str) or not host.startswith("A "):
            raise SystemExit("refusing hostname rule without trusted A-cache hint")
        rule["dest_dns"] = config.validate_dest_dns_name("prompt", host[2:])
    else:
        rule["dest"] = request["dst"]
    data[family_rules].append(rule)
    if request["source"] not in rules:
        # New sources get the same empty in-memory shape as an empty rule file on disk
        rules[request["source"]] = {"ip": [], "dns": []}
    runtime_rule = dict(rule)
    if hostname_action:
        runtime_rule["_resolved_dests"] = request.get("_resolved_dests") or config.resolve_dest_dns("prompt", rule["dest_dns"])
    rules[request["source"]]["ip"].append(runtime_rule)
