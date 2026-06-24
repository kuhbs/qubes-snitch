# YAML config and policy loading for Qubes Snitch
# Paths are passed in by the daemon/tests so one validator is used everywhere

import ipaddress
import re

import dns.exception
import dns.rdatatype

from qubes_snitch.dns import LIVE_DNS_QNAME_RE, LIVE_DNS_SRV_QNAME_RE, SUPPORTED_DNS_QTYPES, dns_qname_is_ipv6_reverse
import yaml

from qubes_snitch.packets import normalize_port


SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$")
FLOW_PROTOS = {"tcp", "udp", "icmp"}
PROMPT_COLOR_PROTOS = {"tcp", "udp"}
PROMPT_COLOR_GROUPS = {"encrypted", "unencrypted"}
PROMPT_COLUMN_WIDTH_KEYS = {"queue", "source", "target", "dns", "service"}
PROMPT_COLUMN_WIDTH_RANGES = {
    "queue": (1, 20),
    "source": (5, 80),
    "target": (10, 200),
    "dns": (10, 200),
    "service": (5, 80),
}
RESERVED_SOURCES = {"unknown"}
DISPVM_POLICY_PREFIX = "dispvm-"
DEFAULT_DVM_TEMPLATE = "default-dvm"
NUMBERED_DISPVM_RE = re.compile(r"^disp[0-9]{1,4}$")


def validate_source_name(source, source_name):
    # Source names become rule filenames and nft chain inputs, so reject path-like and reserved identities
    if not SOURCE_NAME_RE.fullmatch(source):
        raise SystemExit(f"{source_name}: invalid source name: {source}")
    if source in RESERVED_SOURCES or source.startswith(DISPVM_POLICY_PREFIX):
        raise SystemExit(f"{source_name}: reserved source name: {source}")


def validate_qubes_vm_name(source, vm_class, source_name):
    # unknown and disp-like names collide with Snitch sentinels and numbered DispVM policy files
    if "unknown" in source:
        raise SystemExit(f"{source_name}: reserved VM name contains unknown: {source}")
    if "disp" in source and vm_class != "DispVM":
        raise SystemExit(f"{source_name}: reserved disp VM name for non-DispVM: {source}")


class UniqueKeyLoader(yaml.SafeLoader):
    # YAML policy is ordered and hand-editable; duplicate keys are mistakes, not overrides
    pass


def construct_mapping_without_duplicates(loader, node, deep=False):
    # Build the mapping one key at a time so duplicate YAML keys fail before PyYAML can overwrite them
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping_without_duplicates)


def read_yaml(path):
    # Broken YAML is fatal because a firewall should fail closed, not guess defaults and accidentally allow traffic
    with path.open("r", encoding="utf-8") as handle:
        try:
            data = yaml.load(handle, Loader=UniqueKeyLoader)
        except (yaml.YAMLError, ValueError, TypeError) as error:
            raise SystemExit(f"{path}: invalid YAML: {error}")
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected YAML mapping")
    return data


def parse_limit_rate(value):
    # Accept nft-style rates like 3/minute so config.yml can drive both nft logging and Python syslog throttling
    text = str(value)
    match = re.fullmatch(r"([1-9][0-9]*)/(second|minute|hour|day)", text)
    if not match:
        raise ValueError("expected nftables rate like 3/minute")
    periods = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    return int(match.group(1)), periods[match.group(2)]


def validate_prompt_protocol_colors(config_file, value):
    # This is terminal coloring only: listed encrypted flows are green, listed plaintext/normal flows are yellow, unlisted NET flows are red
    if not isinstance(value, dict) or set(value) != PROMPT_COLOR_GROUPS:
        raise SystemExit(f"{config_file}: prompt_protocol_colors must contain exactly encrypted and unencrypted")
    normalized = {}
    used = {}
    for group in ("encrypted", "unencrypted"):
        if not isinstance(value[group], list):
            raise SystemExit(f"{config_file}: prompt_protocol_colors.{group} must be a list")
        normalized[group] = set()
        for entry in value[group]:
            if not isinstance(entry, dict) or set(entry) != {"proto", "port"}:
                raise SystemExit(f"{config_file}: prompt_protocol_colors.{group} entries must have proto and port")
            proto = entry["proto"]
            port = entry["port"]
            if proto not in PROMPT_COLOR_PROTOS:
                raise SystemExit(f"{config_file}: prompt_protocol_colors.{group} proto must be tcp or udp")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise SystemExit(f"{config_file}: prompt_protocol_colors.{group} port must be an integer from 1 to 65535")
            key = (proto, str(port))
            if key in used:
                raise SystemExit(f"{config_file}: {proto}/{port} is listed in both {used[key]} and {group}")
            used[key] = group
            normalized[group].add(key)
    return normalized


def validate_prompt_column_widths(config_file, value):
    # Widths are terminal cell counts for the line-based prompt; exact keys keep layout review simple
    if not isinstance(value, dict) or set(value) != PROMPT_COLUMN_WIDTH_KEYS:
        raise SystemExit(f"{config_file}: prompt_column_widths must contain exactly queue, source, target, dns, and service")
    normalized = {}
    for key in ("queue", "source", "target", "dns", "service"):
        width = value[key]
        minimum, maximum = PROMPT_COLUMN_WIDTH_RANGES[key]
        if not isinstance(width, int) or isinstance(width, bool) or not minimum <= width <= maximum:
            raise SystemExit(f"{config_file}: prompt_column_widths.{key} must be an integer from {minimum} to {maximum}")
        normalized[key] = width
    return normalized


def read_config(config_file):
    # config.yml is intentionally small: UI, queue sizes, DNS cache caps, default DispVM name, and log throttling only
    data = read_yaml(config_file)
    # Exact keys keep config review simple: a typo aborts instead of silently falling back to hidden Python defaults
    expected = {"theme", "notify_send", "notify_send_timeout", "pending_queue_size", "dns_cache_max_per_source", "dns_cache_max_global", "dns_cache_refresh_workers", "default_disposable_vm_name", "limit_rate", "burst", "log_bucket_max_entries", "prompt_column_widths", "prompt_protocol_colors"}
    if set(data) != expected:
        raise SystemExit(f"{config_file}: expected exactly theme, notify_send, notify_send_timeout, pending_queue_size, dns_cache_max_per_source, dns_cache_max_global, dns_cache_refresh_workers, default_disposable_vm_name, limit_rate, burst, log_bucket_max_entries, prompt_column_widths, and prompt_protocol_colors")
    if data["theme"] not in ("dark", "light"):
        raise SystemExit(f"{config_file}: theme must be dark or light")
    if not isinstance(data["notify_send"], bool):
        raise SystemExit(f"{config_file}: notify_send must be True or False")
    # Python bool is a subclass of int, so integer checks must reject bool explicitly
    if not isinstance(data["notify_send_timeout"], int) or isinstance(data["notify_send_timeout"], bool) or not 1000 <= data["notify_send_timeout"] <= 3600000:
        raise SystemExit(f"{config_file}: notify_send_timeout must be an integer from 1000 to 3600000 milliseconds")
    if not isinstance(data["pending_queue_size"], int) or isinstance(data["pending_queue_size"], bool) or not 1 <= data["pending_queue_size"] <= 10000:
        raise SystemExit(f"{config_file}: pending_queue_size must be an integer from 1 to 10000")
    if not isinstance(data["dns_cache_max_per_source"], int) or isinstance(data["dns_cache_max_per_source"], bool) or not 1 <= data["dns_cache_max_per_source"] <= 1000000:
        raise SystemExit(f"{config_file}: dns_cache_max_per_source must be an integer from 1 to 1000000")
    if not isinstance(data["dns_cache_max_global"], int) or isinstance(data["dns_cache_max_global"], bool) or data["dns_cache_max_global"] < data["dns_cache_max_per_source"]:
        raise SystemExit(f"{config_file}: dns_cache_max_global must be an integer greater than or equal to dns_cache_max_per_source")
    if not isinstance(data["dns_cache_refresh_workers"], int) or isinstance(data["dns_cache_refresh_workers"], bool) or not 1 <= data["dns_cache_refresh_workers"] <= 1024:
        raise SystemExit(f"{config_file}: dns_cache_refresh_workers must be an integer from 1 to 1024")
    if not isinstance(data["default_disposable_vm_name"], str):
        raise SystemExit(f"{config_file}: default_disposable_vm_name must be a string")
    validate_source_name(data["default_disposable_vm_name"], config_file)
    validate_qubes_vm_name(data["default_disposable_vm_name"], "TemplateVM", config_file)
    try:
        parse_limit_rate(data["limit_rate"])
    except ValueError as error:
        raise SystemExit(f"{config_file}: limit rate {error}")
    if not isinstance(data["burst"], int) or isinstance(data["burst"], bool) or not 1 <= data["burst"] <= 10000:
        raise SystemExit(f"{config_file}: burst must be an integer from 1 to 10000")
    # Log bucket count is a memory bound for attacker-shaped reject keys, not a logging rate
    if not isinstance(data["log_bucket_max_entries"], int) or isinstance(data["log_bucket_max_entries"], bool) or not 1 <= data["log_bucket_max_entries"] <= 1000000:
        raise SystemExit(f"{config_file}: log_bucket_max_entries must be an integer from 1 to 1000000")
    data["prompt_column_widths"] = validate_prompt_column_widths(config_file, data["prompt_column_widths"])
    data["prompt_protocol_colors"] = validate_prompt_protocol_colors(config_file, data["prompt_protocol_colors"])
    return data


def dispvm_policy_source(source, vm_class, template, default_dvm_template=DEFAULT_DVM_TEMPLATE):
    # Purpose-specific DispVM bases intentionally share one stable policy file, for example dispvm-app-surf.yml
    # A live disp1234.yml file is temporary because numbered DispVM names are reused by Qubes for unrelated future VMs
    # Restarting qubes-snitchd deletes numbered DispVM files before loading policy so stale disp1234 rules cannot persist
    # Therefore persistent user-edited rules for purpose-specific disposables must live on the base as dispvm-<base>.yml
    if vm_class != "DispVM":
        return source
    validate_source_name(template, "DispVM template")
    validate_qubes_vm_name(template, "TemplateVM", "DispVM template")
    if template in (default_dvm_template, DEFAULT_DVM_TEMPLATE):
        # Generic default DispVM policy is temporary; non-numbered rows are ignored so stale qvm-ls data cannot abort startup
        if not NUMBERED_DISPVM_RE.fullmatch(source):
            return None
        return source
    return f"{DISPVM_POLICY_PREFIX}{template}"


def dispvm_display_source(source, vm_class, template):
    # The CLI shows both the live disposable name and its base so prompts stay understandable
    if vm_class != "DispVM":
        return source
    return f"{source}({template})"


def parse_sources_output(text, source_name="qrexec source map", default_dvm_template=DEFAULT_DVM_TEMPLATE):
    # The dom0 qrexec service sends every VM row with an IP so paused VMs are covered before they unpause
    by_name = {}
    by_ip = {}
    labels = {}
    display_by_ip = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 5:
            raise SystemExit(f"{source_name}: expected name|ip|label|class|template line: {line}")
        source, ip, label, vm_class, template = parts
        if not ip or ip == "-":
            continue
        validate_source_name(source, source_name)
        validate_qubes_vm_name(source, vm_class, source_name)
        if vm_class not in ("AppVM", "TemplateVM", "StandaloneVM", "DispVM"):
            raise SystemExit(f"{source_name}: unsupported VM class: {vm_class}")
        if vm_class == "DispVM" and (not template or template == "-"):
            raise SystemExit(f"{source_name}: DispVM missing template: {source}")
        policy_source = dispvm_policy_source(source, vm_class, template, default_dvm_template)
        if policy_source is None:
            continue
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise SystemExit(f"{source_name}: non-IPv4 source address is unsupported: {ip}")
        if ip in by_ip:
            raise SystemExit(f"{source_name}: duplicate source IP {ip}")
        display_source = dispvm_display_source(source, vm_class, template)
        by_name.setdefault(policy_source, []).append(ip)
        by_ip[ip] = policy_source
        display_by_ip[ip] = display_source
        if policy_source in labels and labels[policy_source] != label:
            raise SystemExit(f"{source_name}: conflicting labels for {policy_source}")
        labels[policy_source] = label
    return by_name, by_ip, labels, display_by_ip


def validate_dns_rule(path, rule):
    # Hand-written DNS rules must fail closed instead of silently becoming dead policy
    if not isinstance(rule["qname"], str):
        raise SystemExit(f"{path}: invalid DNS qname: {rule['qname']}")
    qname = rule["qname"].rstrip(".").lower()
    # Manual wildcard DNS policy strips the leading *. before validating the real suffix labels
    # Wildcards are intentionally manual policy only: live DNS requests create exact qname rules, not wildcard rules
    labels = qname[2:].split(".") if qname.startswith("*.") else qname.split(".")
    # Reject IPv6 reverse names, overlong DNS names, single-label names, overlong labels, and punycode/IDN labels
    if dns_qname_is_ipv6_reverse(qname) or len(qname) > 253 or len(labels) < 2 or any(len(label) > 63 or label.startswith("xn--") for label in labels):
        raise SystemExit(f"{path}: invalid DNS qname: {rule['qname']}")
    qtype_text = str(rule["qtype"]).upper()
    if qtype_text.startswith("TYPE") or qtype_text.isdigit():
        raise SystemExit(f"{path}: unsupported DNS qtype: {rule['qtype']}")
    try:
        qtype_value = dns.rdatatype.from_text(qtype_text)
    except dns.exception.DNSException:
        raise SystemExit(f"{path}: invalid DNS qtype: {rule['qtype']}")
    canonical_qtype = dns.rdatatype.to_text(qtype_value).upper()
    if canonical_qtype == "AAAA" or canonical_qtype not in SUPPORTED_DNS_QTYPES:
        raise SystemExit(f"{path}: unsupported DNS qtype: {rule['qtype']}")
    if qname.startswith("*."):
        valid_qname = bool(LIVE_DNS_QNAME_RE.fullmatch(qname[2:]))
    elif canonical_qtype == "SRV":
        valid_qname = bool(LIVE_DNS_SRV_QNAME_RE.fullmatch(qname))
    else:
        valid_qname = bool(LIVE_DNS_QNAME_RE.fullmatch(qname))
    if not valid_qname:
        raise SystemExit(f"{path}: invalid DNS qname: {rule['qname']}")
    rule["qname"] = qname
    rule["qtype"] = canonical_qtype


def validate_rule_file(path, data):
    # Manual rule files must keep this exact schema so nft rendering never has to guess missing fields
    if set(data) != {"rules4", "dns"}:
        raise SystemExit(f"{path}: expected exactly rules4 and dns")
    for key in ("rules4", "dns"):
        if not isinstance(data[key], list):
            raise SystemExit(f"{path}: {key} must be a list")
    for rule in data["rules4"]:
        if not isinstance(rule, dict):
            raise SystemExit(f"{path}: every flow rule must be a mapping")
        if set(rule) != {"ptr", "dest", "proto", "port", "action"}:
            raise SystemExit(f"{path}: every flow rule must have ptr, dest, proto, port, action")
        if rule["action"] not in ("allow", "reject"):
            raise SystemExit(f"{path}: invalid action: {rule['action']}")
        proto = str(rule["proto"])
        if proto.isdigit():
            raise SystemExit(f"{path}: use protocol names instead of numeric proto {proto}")
        if proto not in FLOW_PROTOS:
            raise SystemExit(f"{path}: invalid proto: {rule['proto']}")
        rule["proto"] = proto
        if isinstance(rule["dest"], list) or isinstance(rule["port"], list):
            raise SystemExit(f"{path}: dest and port must be scalar values")
        if not isinstance(rule["port"], str):
            raise SystemExit(f"{path}: port must be a quoted string")
        if rule["dest"] != "any":
            try:
                network = ipaddress.ip_network(str(rule["dest"]), strict=False)
            except ValueError:
                raise SystemExit(f"{path}: invalid destination: {rule['dest']}")
            if network.version != 4:
                raise SystemExit(f"{path}: rules4 contains non-IPv4 destination")
            if str(network) == "0.0.0.0/0":
                raise SystemExit(f"{path}: use dest: any instead of 0.0.0.0/0")
        if proto not in ("tcp", "udp") and rule["port"] != "any":
            raise SystemExit(f"{path}: only tcp and udp rules may specify ports")
        try:
            normalize_port(rule["port"], rule["proto"])
        except (OSError, ValueError):
            raise SystemExit(f"{path}: invalid port for {rule['proto']}: {rule['port']}")
    for rule in data["dns"]:
        if not isinstance(rule, dict):
            raise SystemExit(f"{path}: every DNS rule must be a mapping")
        if set(rule) != {"qname", "qtype", "action"}:
            raise SystemExit(f"{path}: every DNS rule must have qname, qtype, action")
        if rule["action"] not in ("allow", "reject"):
            raise SystemExit(f"{path}: invalid DNS action: {rule['action']}")
        validate_dns_rule(path, rule)


def empty_rule_file(path):
    # Empty rule files are explicit YAML lists so later loads do not need hidden defaults
    path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")


def load_rules(rules_dir, default_disposable_vm_name=DEFAULT_DVM_TEMPLATE):
    # The filename is the source identity, so each YAML file only stores rules for that one source
    rules = {}
    for path in sorted(rules_dir.glob("*.yml")):
        if not SOURCE_NAME_RE.fullmatch(path.stem):
            raise SystemExit(f"{path}: invalid source filename")
        if path.stem in RESERVED_SOURCES:
            raise SystemExit(f"{path}: reserved source filename")
        forbidden_default_policy = f"dispvm-{default_disposable_vm_name}"
        if path.stem in ("dispvm-default-dvm", forbidden_default_policy):
            raise SystemExit(f"{path}: default DisposableVM policy is not supported")
        data = read_yaml(path)
        validate_rule_file(path, data)
        rules[path.stem] = {"ip": data["rules4"], "dns": data["dns"]}
    return rules
