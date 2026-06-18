# nftables rendering for Qubes Snitch
# Validated YAML policy becomes one private inet table that hooks the forward path

import hashlib
import ipaddress
import subprocess

from qubes_snitch.packets import normalize_port


def nft_chain_name(source):
    # Keep chain names readable but append a hash so app-a, app_a, and app.a cannot collide after sanitizing
    safe = "".join(ch if ch.isalnum() else "_" for ch in source)
    digest = hashlib.blake2s(source.encode("utf-8"), digest_size=4).hexdigest()
    return f"source_{safe}_{digest}"


def nft_quote(text):
    # Quote log prefixes safely because source names are human text placed into nft syntax
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def nft_value(value):
    # Destination matches are intentionally scalar: any, one IPv4 address, or one IPv4 CIDR network
    if value == "any":
        return None
    network = ipaddress.ip_network(str(value), strict=False)
    if network.version != 4:
        raise SystemExit(f"non-IPv4 destination is unsupported: {value}")
    return str(value)


def nft_port(value, proto):
    # Convert service names and validate numeric/range ports before inserting the value into nft syntax
    port = normalize_port(value, proto)
    if port == "any":
        return None
    return port


def render_match(rule):
    # Build the nft match expression from the tiny rule schema: destination, protocol, and optional port
    parts = ["meta", "nfproto", "ipv4"]
    dest = nft_value(rule["dest"])
    port = nft_port(rule["port"], rule["proto"])
    if dest:
        parts += ["ip", "daddr", dest]
    if rule["proto"] in ("tcp", "udp"):
        if port:
            parts += [rule["proto"], "dport", port]
        else:
            parts += ["meta", "l4proto", rule["proto"]]
    elif rule["proto"] == "icmp":
        parts += ["ip", "protocol", "icmp"]
    else:
        parts += ["meta", "l4proto", str(rule["proto"])]
    return " ".join(parts)


def udp_rule_includes_dns(rule):
    # Broad UDP allows cannot bypass domain prompts, so rules covering UDP/53 still queue DNS packets
    if rule["proto"] != "udp":
        return False
    port = normalize_port(rule["port"], "udp")
    if port == "any" or port == "53":
        return True
    if "-" not in port:
        return False
    start, end = [int(part) for part in port.split("-", 1)]
    return start <= 53 <= end


def render_dns_queue_match(rule):
    # Keep the original destination constraint but narrow the queued packet to UDP destination port 53
    parts = ["meta", "nfproto", "ipv4"]
    dest = nft_value(rule["dest"])
    if dest:
        parts += ["ip", "daddr", dest]
    parts += ["udp", "dport", "53"]
    return " ".join(parts)


def nft_log_limit(config):
    # config.yml stores nft-style limit/burst text so rendered log rules are easy to read
    return f"limit rate {config['limit_rate']} burst {config['burst']} packets"


def render_rule(source, rule, config, queue_num):
    # Saved reject rules log before rejecting so journalctl shows the readable source and exact match
    match = render_match(rule)
    if rule["action"] == "allow":
        if udp_rule_includes_dns(rule):
            # A broad UDP allow still sends UDP/53 through Python so domain policy cannot be bypassed
            queue_rule = f"  {render_dns_queue_match(rule)} queue num {queue_num}"
            if normalize_port(rule["port"], "udp") == "53":
                return queue_rule
            return f"{queue_rule}\n  {match} accept"
        return f"  {match} accept"
    if rule["action"] == "reject":
        prefix = nft_quote(f"QUBES-SNITCH {source} reject ")
        return f"  {match} {nft_log_limit(config)} log prefix {prefix} counter reject with icmpx admin-prohibited"
    raise SystemExit(f"{source}: unknown action {rule['action']}")


def render_established_reply_rule(source, source_ip, rule, config, reply_source=None):
    # Reply packets reverse source/destination, so mirror source rules with sport/daddr matches
    # Keep YAML order so broad later rules cannot override earlier specific decisions
    parts = ["meta", "nfproto", "ipv4"]
    dest = nft_value(rule["dest"])
    port = nft_port(rule["port"], rule["proto"])
    if reply_source:
        # Broad inter-VM reply policy is constrained to known peer IPs before source jumps to avoid unknown-source bypass
        parts += ["ip", "saddr", reply_source]
    elif dest:
        parts += ["ip", "saddr", dest]
    parts += ["ip", "daddr", source_ip]
    if rule["proto"] in ("tcp", "udp"):
        if port:
            parts += [rule["proto"], "sport", port]
        else:
            parts += ["meta", "l4proto", rule["proto"]]
    elif rule["proto"] == "icmp":
        parts += ["ip", "protocol", "icmp"]
    else:
        parts += ["meta", "l4proto", str(rule["proto"])]
    parts += ["ct", "state", "established,related", "ct", "direction", "reply"]
    match = " ".join(parts)
    if rule["action"] == "allow":
        return f"  {match} accept"
    if rule["action"] == "reject":
        prefix = nft_quote(f"QUBES-SNITCH {source} reject ")
        return f"  {match} {nft_log_limit(config)} log prefix {prefix} counter reject with icmpx admin-prohibited"
    raise SystemExit(f"{source}: unknown action {rule['action']}")


def nft_source_jump(ip, chain):
    # Snitch intentionally does not duplicate Qubes' per-vif anti-spoofing match here
    # Source IPs are packet-header fields a VM could forge, but Qubes blocks that before Snitch sees normal forwarded traffic
    # Qubes installs `table ip qubes` from `qubes-antispoof.nft` with `iifname . ip saddr @allowed`
    # Those Qubes-owned nftables rules run inside the same network-providing VM as Snitch, for example sys-snitch
    # Snitch must not edit Qubes-owned tables such as `table ip qubes`; Snitch only owns its private `table inet qubes_snitch`
    # Reference: https://github.com/QubesOS/qubes-core-agent-linux/blob/main/network/qubes-antispoof.nft
    # Qubes fills that `allowed` set in `vif-route-qubes` when Xen hotplug brings a client vif online
    # Reference: https://github.com/QubesOS/qubes-core-agent-linux/blob/main/network/vif-route-qubes
    # The same hotplug script also installs `ip route <vm-ip> dev <vifX.Y>` for the network-providing VM
    # Because that Qubes raw/prerouting anti-spoof layer already enforces `vif + source IP`, Snitch policy stays VM/IP based
    # Adding `iifname "vifX.Y" ip saddr ...` to every Snitch source jump would be redundant under supported Qubes networking
    # The important Snitch invariant is that unknown IPs never become promptable raw-IP policy sources
    # If duplicate VM IPs or broken Qubes source metadata become a concern, handle that during source-map refresh, not per packet here
    if ipaddress.ip_address(ip).version != 4:
        raise SystemExit(f"non-IPv4 source is unsupported: {ip}")
    return f"  ip saddr {ip} jump {chain}"


def render_fail_closed_nft(config, nft_table, queue_num):
    # Startup fallback: no source map yet, so every forward packet goes through Python or hits base policy drop if no listener exists
    lines = [
        f"destroy table inet {nft_table}",
        f"table inet {nft_table} {{",
        *render_local_input_chain(config),
        " chain forward {",
        "  type filter hook forward priority filter; policy drop;",
        f"  ct state invalid {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH invalid ')} counter reject with icmpx admin-prohibited",
        f"  meta nfproto ipv4 queue num {queue_num}",
        f"  {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH fail-closed reject ')} counter reject with icmpx admin-prohibited",
        " }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def render_local_input_chain(config):
    # Snitch source policy controls forwarded traffic, but packets addressed to the firewall VM itself use the input hook
    # Client VMs should not talk directly to local NetVM/gateway services when Snitch says their traffic is rejected
    # Match only Qubes client vif interfaces so loopback, upstream eth0, and the firewall VM's own outbound traffic are untouched
    return [
        " chain input {",
        "  type filter hook input priority filter; policy accept;",
        f"  iifname \"vif*\" fib daddr type local {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH local reject ')} counter reject with icmpx admin-prohibited",
        " }",
    ]


def render_nft(sources, rules, config, nft_table, queue_num):
    # Each source gets its own chain so fallback reject logs include the readable source name
    lines = [
        f"destroy table inet {nft_table}",
        f"table inet {nft_table} {{",
        *render_local_input_chain(config),
        " chain forward {",
        "  type filter hook forward priority filter; policy drop;",
    ]
    # Established reply rules render before source jumps so replies do not look like new outbound peer traffic
    for source, ips in sources.items():
        for ip in ips:
            for rule in rules[source]["ip"]:
                lines.append(render_established_reply_rule(source, ip, rule, config))
    # UDP/53 source jumps come before generic source jumps because DNS has resolver and qname policy layers
    for source, ips in sources.items():
        for ip in ips:
            lines.append(f"  ip saddr {ip} udp dport 53 jump {nft_chain_name(source)}")
    for source, ips in sources.items():
        for ip in ips:
            lines.append(nft_source_jump(ip, nft_chain_name(source)))
    # Reply packets use the remote host as source, so accept only conntrack reply-direction traffic to known VM IPs
    # A broad or original-direction established accept here would let stale/unknown Qubes source IPs bypass daemon-fatal source checks
    for ips in sources.values():
        for ip in ips:
            lines.append(f"  ip daddr {ip} ct state established,related ct direction reply accept")
    # Unknown-source packets reach Python so it can alert and fail hard on broken Qubes source identity
    lines.append(f"  jump {nft_chain_name('unknown')}")
    lines.append(f"  ct state invalid {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH invalid ')} counter reject with icmpx admin-prohibited")
    lines.append(" }")
    for source in sources:
        lines.append(f" chain {nft_chain_name(source)} {{")
        lines.append(f"  ct state invalid {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH ' + source + ' invalid ')} counter reject with icmpx admin-prohibited")
        lines.append(f"  udp dport 53 queue num {queue_num}")
        for rule in rules[source]["ip"]:
            lines.append(render_rule(source, rule, config, queue_num))
        lines.append(f"  queue num {queue_num}")
        lines.append(f"  {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH ' + source + ' reject ')} counter reject with icmpx admin-prohibited")
        lines.append(" }")
    lines.append(f" chain {nft_chain_name('unknown')} {{")
    lines.append(f"  meta nfproto ipv4 queue num {queue_num}")
    lines.append(f"  {nft_log_limit(config)} log prefix {nft_quote('QUBES-SNITCH unknown reject ')} counter reject with icmpx admin-prohibited")
    lines.append(" }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def load_nft(nft_file, sources, rules, config, nft_table, queue_num):
    # Run nft -c first so a bad render cannot replace the currently loaded firewall table
    nft_file.write_text(render_nft(sources, rules, config, nft_table, queue_num), encoding="utf-8")
    subprocess.run(["nft", "-c", "-f", str(nft_file)], check=True)
    subprocess.run(["nft", "-f", str(nft_file)], check=True)


def load_fail_closed_nft(nft_file, config, nft_table, queue_num):
    # Install the no-bypass startup table before fragile source discovery, so failure is never allow-all
    nft_file.write_text(render_fail_closed_nft(config, nft_table, queue_num), encoding="utf-8")
    subprocess.run(["nft", "-c", "-f", str(nft_file)], check=True)
    subprocess.run(["nft", "-f", str(nft_file)], check=True)
