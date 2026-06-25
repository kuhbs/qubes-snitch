# Runtime DNS hint cache for qubes-snitchd
# Hints are display-only; Snitch never parses resolver replies for policy

from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.reversename

from qubes_snitch import alerts_runtime
from qubes_snitch.security_checks import has_non_ascii

DNS_HINT_QTYPES = {"A", "CNAME"}
DNS_LOOKUP_LIFETIME = 3.0
DNS_REFRESH_FAILURE_TTL = 60
DNS_PTR_REJECT = object()


def response_matches_qname(response, qname, qtype, label):
    # Shared CDN and mail IPs can have multiple names, so only delete labels owned by this qname
    return response and response["qname"] == qname and response["qtype"] == qtype and response["label"] == label


def prune_qname_cache(ctx):
    # Keep qname history consistent with IP labels after response-cache eviction
    for key, cached in list(ctx.DNS_QNAME_CACHE.items()):
        source, qtype, qname = key
        labels = {}
        for ip, label in cached["labels"].items():
            response = ctx.DNS_RESPONSE_CACHE.get((source, ip))
            if response_matches_qname(response, qname, qtype, label):
                labels[ip] = label
        cached["labels"] = labels


def evict_dns_cache_for_source(ctx, source):
    # If a VM exceeds its cache budget, drop stale entries first, then entries that expire soonest
    limit = ctx.CONFIG["dns_cache_max_per_source"]
    keys = [key for key in ctx.DNS_RESPONSE_CACHE if key[0] == source]
    overflow = len(keys) - limit
    if overflow <= 0:
        return
    now = ctx.time.monotonic()
    keys.sort(key=lambda key: (ctx.DNS_RESPONSE_CACHE[key]["expires_at"] > now, ctx.DNS_RESPONSE_CACHE[key]["expires_at"]))
    for key in keys[:overflow]:
        del ctx.DNS_RESPONSE_CACHE[key]
    prune_qname_cache(ctx)


def evict_dns_cache_global(ctx):
    # Keep the firewall VM memory bounded across all sources
    overflow = len(ctx.DNS_RESPONSE_CACHE) - ctx.CONFIG["dns_cache_max_global"]
    if overflow <= 0:
        return
    now = ctx.time.monotonic()
    keys = sorted(ctx.DNS_RESPONSE_CACHE, key=lambda key: (ctx.DNS_RESPONSE_CACHE[key]["expires_at"] > now, ctx.DNS_RESPONSE_CACHE[key]["expires_at"]))
    for key in keys[:overflow]:
        del ctx.DNS_RESPONSE_CACHE[key]
    prune_qname_cache(ctx)


def evict_qname_cache_for_source(ctx, source):
    # Negative qname caches are bounded separately because they may not create IP labels
    limit = ctx.CONFIG["dns_cache_max_per_source"]
    keys = [key for key in ctx.DNS_QNAME_CACHE if key[0] == source]
    overflow = len(keys) - limit
    if overflow <= 0:
        return
    now = ctx.time.monotonic()
    keys.sort(key=lambda key: (ctx.DNS_QNAME_CACHE[key]["expires_at"] > now, ctx.DNS_QNAME_CACHE[key]["expires_at"]))
    for key in keys[:overflow]:
        del ctx.DNS_QNAME_CACHE[key]


def evict_qname_cache_global(ctx):
    # Keep negative and low-cardinality qname history bounded across all sources
    overflow = len(ctx.DNS_QNAME_CACHE) - ctx.CONFIG["dns_cache_max_global"]
    if overflow <= 0:
        return
    now = ctx.time.monotonic()
    keys = sorted(ctx.DNS_QNAME_CACHE, key=lambda key: (ctx.DNS_QNAME_CACHE[key]["expires_at"] > now, ctx.DNS_QNAME_CACHE[key]["expires_at"]))
    for key in keys[:overflow]:
        del ctx.DNS_QNAME_CACHE[key]


def dns_rule_refreshable(qname, qtype):
    # Wildcard policy cannot be refreshed because there is no concrete owner name to resolve
    return qtype in DNS_HINT_QTYPES and not qname.startswith("*.")


def answer_ttl(answers):
    return max(1, int(getattr(getattr(answers, "rrset", None), "ttl", 60) or 60))


def a_answers(qname, label):
    answers = dns.resolver.resolve(qname, "A", lifetime=DNS_LOOKUP_LIFETIME)
    ttl = answer_ttl(answers)
    return ({answer.to_text(): label for answer in answers}, ttl)


def resolve_dns_rule(qname, qtype):
    if qtype in ("A", "CNAME"):
        return a_answers(qname, qname)
    return {}, DNS_REFRESH_FAILURE_TTL


def remove_old_qname_ips(ctx, source, qname, qtype):
    # Refreshes replace only labels from the same qname so unrelated labels for shared IPs survive
    cached = ctx.DNS_QNAME_CACHE.get((source, qtype, qname))
    if not cached:
        return
    for ip, label in cached["labels"].items():
        response = ctx.DNS_RESPONSE_CACHE.get((source, ip))
        if response_matches_qname(response, qname, qtype, label):
            del ctx.DNS_RESPONSE_CACHE[(source, ip)]


def store_dns_labels(ctx, source, qname, qtype, labels, ttl):
    now = ctx.time.monotonic()
    expires_at = now + ttl
    with ctx.DNS_CACHE_LOCK:
        remove_old_qname_ips(ctx, source, qname, qtype)
        ctx.DNS_QNAME_CACHE[(source, qtype, qname)] = {"labels": labels, "expires_at": expires_at}
        for ip, label in labels.items():
            ctx.DNS_RESPONSE_CACHE[(source, ip)] = {"label": label, "qname": qname, "qtype": qtype, "expires_at": expires_at}
        evict_dns_cache_for_source(ctx, source)
        evict_dns_cache_global(ctx)
        evict_qname_cache_for_source(ctx, source)
        evict_qname_cache_global(ctx)


def refresh_dns_rule(ctx, source, qname, qtype):
    # Resolver refresh is lazy and runs only in the CLI thread, never in NFQUEUE verdict handling
    if not dns_rule_refreshable(qname, qtype):
        return {}
    try:
        labels, ttl = resolve_dns_rule(qname, qtype)
    except Exception as error:
        ctx.syslog.syslog(ctx.syslog.LOG_INFO, f"QUBES-SNITCH DNS hint refresh failed SOURCE={source} QTYPE={qtype} QNAME={qname} REASON={error}")
        labels = {}
        ttl = DNS_REFRESH_FAILURE_TTL
    store_dns_labels(ctx, source, qname, qtype, labels, ttl)
    return labels


def allowed_dns_hint_rules(ctx, source):
    # Copy concrete allow rules under policy lock; DNS network lookups happen after releasing it
    rules = []
    with ctx.POLICY_LOCK:
        for rule in ctx.RULES.get(source, {"dns": []})["dns"]:
            qname = str(rule["qname"]).lower()
            qtype = str(rule["qtype"]).upper()
            if rule["action"] == "allow" and dns_rule_refreshable(qname, qtype):
                rules.append((qname, qtype))
    return rules


def fresh_response_label(ctx, source, ip):
    now = ctx.time.monotonic()
    with ctx.DNS_CACHE_LOCK:
        cached = ctx.DNS_RESPONSE_CACHE.get((source, ip))
        if cached and cached["expires_at"] > now:
            return cached["label"]
        return None


def stale_response_rule(ctx, source, ip):
    now = ctx.time.monotonic()
    with ctx.DNS_CACHE_LOCK:
        cached = ctx.DNS_RESPONSE_CACHE.get((source, ip))
        if cached and cached["expires_at"] <= now:
            return cached["qname"], cached["qtype"]
        return None


def cached_qname_labels(ctx, source, qname, qtype):
    # Fresh negative caches avoid re-resolving every allowed domain for every unknown IP prompt
    now = ctx.time.monotonic()
    with ctx.DNS_CACHE_LOCK:
        cached = ctx.DNS_QNAME_CACHE.get((source, qtype, qname))
        if cached and cached["expires_at"] > now:
            return dict(cached["labels"])
    return None


def qname_labels(ctx, source, qname, qtype):
    labels = cached_qname_labels(ctx, source, qname, qtype)
    if labels is not None:
        return labels
    return refresh_dns_rule(ctx, source, qname, qtype)


def ptr_name(ctx, source, ip):
    # PTR is DNS text from the network; reject Unicode before it can become a prompt display hint
    try:
        reverse = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reverse, "PTR", lifetime=DNS_LOOKUP_LIFETIME)
    except Exception:
        return None
    for answer in answers:
        target = str(answer.target).rstrip(".")
        if has_non_ascii(target):
            alerts_runtime.security_alert(
                ctx,
                ("dns", source, "non-ascii-ptr", ip),
                f"DROP PTR containing non-ASCII text SRC={source} DST={ip}",
            )
            return DNS_PTR_REJECT
        return f"PTR {target}"
    return None


def refresh_dns_rules(ctx, source, rules):
    # Refresh missing or stale qnames together so one slow lookup does not block every later rule
    if not rules:
        return []
    workers = min(ctx.CONFIG["dns_cache_refresh_workers"], len(rules))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(refresh_dns_rule, ctx, source, qname, qtype) for qname, qtype in rules]
        return [future.result() for future in futures]


def lazy_dns_name(ctx, source, ip):
    # Try the stale likely match first, then check every allowed qname without serial DNS stalls
    stale_rule = stale_response_rule(ctx, source, ip)
    if stale_rule:
        labels = refresh_dns_rule(ctx, source, stale_rule[0], stale_rule[1])
        if ip in labels:
            return f"A {labels[ip]}"
    refresh_rules = []
    for qname, qtype in allowed_dns_hint_rules(ctx, source):
        if stale_rule == (qname, qtype):
            continue
        labels = cached_qname_labels(ctx, source, qname, qtype)
        if labels is None:
            refresh_rules.append((qname, qtype))
            continue
        if ip in labels:
            return f"A {labels[ip]}"
    for labels in refresh_dns_rules(ctx, source, refresh_rules):
        if ip in labels:
            return f"A {labels[ip]}"
    return ptr_name(ctx, source, ip)


def cached_dns_name(ctx, source, ip):
    # Packet callbacks use only fresh cache hits, so they never block on resolver I/O
    label = fresh_response_label(ctx, source, ip)
    if label:
        return f"A {label}"
    return None


def add_cached_dns_name(ctx, request):
    # NFQUEUE path only attaches fresh in-memory hints; lazy refresh happens later in the CLI thread
    name = cached_dns_name(ctx, request["source"], request["dst"])
    if name:
        request["host"] = name


def enrich_prompt_request(ctx, request):
    # The CLI thread may spend a bounded amount of time improving a displayed prompt without delaying packet verdicts
    if request.get("kind") == "dns" or request.get("host") or not request.get("dst"):
        return request
    name = lazy_dns_name(ctx, request["source"], request["dst"])
    if name is DNS_PTR_REJECT:
        # The packet that created this prompt was already dropped
        # Discarding the prompt keeps later retries rejected instead of showing Unicode PTR text
        return None
    if name:
        request["host"] = name
    return request
