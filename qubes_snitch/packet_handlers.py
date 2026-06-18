# NFQUEUE packet handlers for qubes-snitchd
# Packet callbacks stay separate from startup, source refresh, and YAML persistence code

from qubes_snitch import alerts_runtime
from qubes_snitch import policy
from qubes_snitch import policy_runtime
from qubes_snitch import queue
from qubes_snitch import sources_runtime
from qubes_snitch.dns import add_dns_query_fields
from qubes_snitch.packets import request_without_body


def queue_prompt(ctx, request):
    # Hold policy lock through queue insertion so source cleanup and CLI saves cannot race a stale prompt into existence
    with ctx.POLICY_LOCK:
        if request["source"] not in ctx.SOURCES_BY_NAME or (request.get("src") and request["src"] not in ctx.SOURCES_BY_NAME[request["source"]]):
            ctx.syslog.syslog(ctx.syslog.LOG_INFO, f"QUBES-SNITCH ignore stale prompt for vanished source: {request['source']}")
            return False
        policy_runtime.ensure_rule_entry(ctx, request["source"])
        # A CLI answer can save policy after the packet thread's first match check; recheck before asking again
        action = policy.matching_action(request, ctx.RULES)
        if action:
            return action
        queue.queue_question(
            request,
            ctx.CONFIG,
            lambda queued: alerts_runtime.log_pending_reject(ctx, queued),
            lambda rejected: alerts_runtime.log_queue_full_reject(ctx, rejected),
            lambda queued: alerts_runtime.notify_prompt(ctx, queued),
        )
    return None


def add_source_label(ctx, request):
    # Only sources resolved through dom0 qrexec have Qubes label colors
    if request["source"] not in ctx.SOURCE_LABELS:
        return
    request["source_label"] = ctx.SOURCE_LABELS[request["source"]]


def add_runtime_request_fields(ctx, request):
    # Unknown source IP means Qubes source identity is inconsistent; refresh once before fail-closed
    with ctx.POLICY_LOCK:
        known = request["src"] in ctx.SOURCES_BY_IP
    if not known:
        sources_runtime.refresh_sources_and_nft(ctx, force=True)
        with ctx.POLICY_LOCK:
            known = request["src"] in ctx.SOURCES_BY_IP
        if known:
            request["source"] = ctx.SOURCES_BY_IP[request["src"]]
            request["display_source"] = ctx.SOURCE_DISPLAY_BY_IP.get(request["src"], request["source"])
            alerts_runtime.log_flow_reject(ctx, request, "source-refresh")
            return False
    if not known:
        alerts_runtime.fatal_security_alert(ctx, ("unknown-source", request["src"]), f"source IP unknown to Qubes SRC={request['src']} DST={request['dst']} PROTO={request['proto']}")
    with ctx.POLICY_LOCK:
        request["source"] = ctx.SOURCES_BY_IP[request["src"]]
        request["display_source"] = ctx.SOURCE_DISPLAY_BY_IP.get(request["src"], request["source"])
        policy_runtime.ensure_rule_entry(ctx, request["source"])
        add_source_label(ctx, request)
    request["host"] = None
    return True


def apply_flow_verdict(packet, decision):
    # Apply the NFQUEUE verdict for one queued packet
    # Qubes-Snitch product policy says reject, while the Python NFQUEUE API exposes that as packet.drop()
    if decision == "allow":
        packet.accept()
    else:
        packet.drop()


def send_dns_refused(ctx, payload, request):
    # The queued packet is on the forward path, so send a new reply instead of reversing that packet in-place
    reply = ctx.dns_reject_payload(payload, request)
    sock = ctx.socket.socket(ctx.socket.AF_INET, ctx.socket.SOCK_RAW, ctx.socket.IPPROTO_RAW)
    try:
        # dns_reject_payload returns a complete IPv4 packet with its own IP header and UDP checksum
        sock.setsockopt(ctx.socket.IPPROTO_IP, ctx.socket.IP_HDRINCL, 1)
        sock.sendto(reply, (request["src"], 0))
    finally:
        sock.close()


def answer_rejected_dns(ctx, packet, payload, request, reason):
    # Always verdict the original query even if raw REFUSED delivery fails
    alerts_runtime.log_dns_reject(ctx, request, reason)
    try:
        send_dns_refused(ctx, payload, request)
    except OSError as error:
        # REFUSED delivery is best-effort UX; the security decision is still rejecting the original query
        ctx.syslog.syslog(ctx.syslog.LOG_INFO, f"QUBES-SNITCH could not send DNS REFUSED SRC={request['src']} QNAME={request.get('qname')} REASON={error}")
    finally:
        packet.drop()


def answer_malformed_dns(ctx, packet, _payload, request):
    # Malformed DNS is suspicious or broken traffic; log it and drop instead of crafting a reply
    alerts_runtime.log_dns_formerr(ctx, request)
    packet.drop()


def answer_unsupported_dns(ctx, packet, payload, request):
    # Unsupported but normal DNS queries get REFUSED so common AAAA lookups fail fast without scary alerts
    answer_rejected_dns(ctx, packet, payload, request, "unsupported")


def handle_dns_domain(ctx, packet, payload, request):
    # Domain prompts are separate from resolver transport prompts and only run after UDP/53 itself is allowed
    if not add_dns_query_fields(request):
        packet.drop()
        return
    if request.get("dns_error", "").startswith("unsupported-"):
        answer_unsupported_dns(ctx, packet, payload, request)
        return
    if request.get("kind") == "dns-error":
        answer_malformed_dns(ctx, packet, payload, request)
        return
    domain_action = policy_runtime.matching_action(ctx, request)
    if domain_action == "allow":
        packet.accept()
        return
    if domain_action == "reject":
        answer_rejected_dns(ctx, packet, payload, request, "rule")
        return
    queued_action = queue_prompt(ctx, request)
    if queued_action == "allow":
        packet.accept()
        return
    if queued_action == "reject":
        answer_rejected_dns(ctx, packet, payload, request, "rule")
        return
    # Pending DNS questions should look like ordinary UDP loss until the user decides
    # If the user allows the domain, the client's next retry can reach the resolver and fill the DNS hint cache
    packet.drop()


def handle_dns_transport(ctx, packet, payload, request):
    # DNS has two layers: resolver transport policy first, then qname/qtype domain policy
    # A VM must be allowed to talk to the resolver before the specific DNS question can be allowed
    flow_action = policy_runtime.matching_action(ctx, request)
    if flow_action == "reject":
        alerts_runtime.log_flow_reject(ctx, request, "rule")
        packet.drop()
        return
    if flow_action is None:
        queued_action = queue_prompt(ctx, request)
        if queued_action == "allow":
            handle_dns_domain(ctx, packet, payload, request)
            return
        if queued_action == "reject":
            alerts_runtime.log_flow_reject(ctx, request, "rule")
            packet.drop()
            return
        # No resolver-transport answer exists yet, so reject this packet and wait for a saved future decision
        apply_flow_verdict(packet, "reject")
        return
    handle_dns_domain(ctx, packet, payload, request)


def handle_flow_packet(ctx, packet, request):
    # Drop raw packet body before queueing normal flow prompts because the CLI only needs semantic fields
    flow_request = request_without_body(request)
    ctx.dns_cache_runtime.add_cached_dns_name(ctx, flow_request)
    action = policy_runtime.matching_action(ctx, flow_request)
    if action:
        apply_flow_verdict(packet, action)
        return
    queued_action = queue_prompt(ctx, flow_request)
    if queued_action:
        apply_flow_verdict(packet, queued_action)
        return
    apply_flow_verdict(packet, "reject")


def handle_packet(ctx, packet):
    # Main NFQUEUE callback: parse, reject malformed packets, enrich source info, then dispatch DNS vs normal flow
    payload = packet.get_payload()
    request = ctx.parse_packet(payload)
    if request is None:
        alerts_runtime.log_unparsed_packet(ctx)
        packet.drop()
        return
    # Parsed packets always have a source IP, so unknown-source identity failures win before malformed handling
    if not add_runtime_request_fields(ctx, request):
        packet.drop()
        return
    if request.get("malformed"):
        alerts_runtime.log_malformed_packet(ctx, request)
        packet.drop()
        return
    if request["proto"] == "udp" and request["dport"] == 53:
        handle_dns_transport(ctx, packet, payload, request)
        return
    handle_flow_packet(ctx, packet, request)
