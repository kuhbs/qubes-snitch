# Runtime logging and notification helpers for qubes-snitchd
# Security alerts stay centralized so every suspicious reject is logged and visibly notified the same way

import syslog

from qubes_snitch import config
from qubes_snitch import notify
from qubes_snitch import queue
from qubes_snitch.display import safe_text
from qubes_snitch.packets import request_port


def log_allowed(ctx, key):
    # Token-bucket throttling keeps repeated Python syslog rejects from flooding journalctl
    # Keys include packet details, so the table must be bounded like the prompt queue and DNS hint cache
    now = ctx.time.monotonic()
    count, seconds = config.parse_limit_rate(ctx.CONFIG["limit_rate"])
    burst = ctx.CONFIG["burst"]

    # Missing keys start full so the first reject is visible immediately
    tokens, updated = ctx.LOG_BUCKETS.get(key, (burst, now))
    tokens = min(burst, tokens + ((now - updated) * count / seconds))
    allowed = tokens >= 1

    # Store suppressed logs too, otherwise a noisy source could reset the bucket by staying below one token
    ctx.LOG_BUCKETS[key] = ((tokens - 1) if allowed else tokens, now)
    ctx.LOG_BUCKETS.move_to_end(key)

    # Evict oldest buckets first so unique attacker-chosen DNS names cannot grow daemon memory forever
    while len(ctx.LOG_BUCKETS) > ctx.CONFIG["log_bucket_max_entries"]:
        ctx.LOG_BUCKETS.popitem(last=False)
    return allowed


def log_dns_reject(ctx, request, reason):
    # Keep qname out of the throttle key so random rejected domains share one bounded source/type bucket
    # The real qname is still printed in the log line that survives throttling
    key = (request["source"], "dns", request["qtype"], reason)
    if not log_allowed(ctx, key):
        return
    source = safe_text(request.get("display_source", request["source"]))
    syslog.syslog(
        syslog.LOG_INFO,
        f"QUBES-SNITCH {source} reject DNS "
        f"SRC={request['src']} DST={request['dst']} "
        f"QTYPE={safe_text(request['qtype'])} QNAME={safe_text(request['qname'])} REASON={safe_text(reason)}",
    )


def log_flow_reject(ctx, request, reason):
    # Python-handled rejects must log too; UDP/53 transport rejects bypass nft reject logging to protect DNS policy
    key = (request["source"], "flow", request["dst"], request["proto"], request_port(request), reason)
    if not log_allowed(ctx, key):
        return
    syslog.syslog(
        syslog.LOG_INFO,
        f"QUBES-SNITCH {safe_text(request.get('display_source', request['source']))} reject NET "
        f"DST={safe_text(request['dst'])} PROTO={safe_text(request['proto'])} DPORT={safe_text(request_port(request))} REASON={safe_text(reason)}",
    )


def log_dns_formerr(ctx, request):
    # DNS packets that are not normal one-question client queries are suspicious, so reject and notify
    reason = request.get("dns_error", "malformed")
    if reason == "unsupported-aaaa":
        security_alert(
            ctx,
            ("dns", request["source"], reason),
            f"REJECT unsupported DNS qtype SRC={request['source']} IP={request['src']} DST={request['dst']} QTYPE=AAAA",
        )
        return
    security_alert(
        ctx,
        ("dns", request["source"], reason),
        f"REJECT malformed DNS SRC={request['source']} IP={request['src']} DST={request['dst']} REASON={reason}",
    )


def log_pending_reject(ctx, request):
    # Unknown traffic is rejected immediately but queued for the user so the next packet can be allowed after a decision
    # Prompt dedupe already uses the exact question key, so log throttling only needs source and kind
    key = (request["source"], request.get("kind", "net"), "pending")
    if not log_allowed(ctx, key):
        return
    if request.get("kind") == "dns":
        text = f"DNS QTYPE={safe_text(request['qtype'])} QNAME={safe_text(request['qname'])}"
    else:
        text = f"NET DST={safe_text(request['dst'])} PROTO={safe_text(request['proto'])} DPORT={safe_text(request_port(request))}"
    syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH {safe_text(request.get('display_source', request['source']))} reject pending {text}")


def log_queue_full_reject(ctx, request):
    # Full queues reject new prompts without hiding what traffic was refused
    key = (request["source"], request.get("kind", "net"), "queue-full")
    if not log_allowed(ctx, key):
        return
    if request.get("kind") == "dns":
        text = f"DNS QTYPE={safe_text(request['qtype'])} QNAME={safe_text(request['qname'])}"
    else:
        text = f"NET DST={safe_text(request['dst'])} PROTO={safe_text(request['proto'])} DPORT={safe_text(request_port(request))}"
    syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH {safe_text(request.get('display_source', request['source']))} reject queue-full {text}")


def notify_prompt(ctx, request):
    # Prompt visibility is part of the firewall contract; if the user cannot see new allow/reject questions, block everything
    # No internet is visible immediately, while journal-only prompt failures are easy to miss
    try:
        notify.alert_notify(request, ctx.CONFIG, ctx.NOTIFY_USER, ctx.NOTIFY_DISPLAY, ctx.NOTIFY_RUNTIME_DIR, ctx.NOTIFY_DBUS)
    except (ctx.subprocess.CalledProcessError, ctx.subprocess.TimeoutExpired, OSError) as error:
        fail_daemon(ctx, f"notify-send failed: {error}")


def fail_daemon(ctx, message):
    # Worker-thread failures use os._exit because raising there would only kill the worker, not the daemon
    if ctx.threading.current_thread() is ctx.threading.main_thread():
        raise SystemExit(message)
    ctx.os._exit(1)


def security_alert(ctx, key, message, priority=syslog.LOG_WARNING):
    # Security alerts must be visible right away, not hidden in journalctl where the user will miss them
    # If notify-send cannot show the alert, fail the daemon so systemd restores fail-closed and internet visibly stops
    if not log_allowed(ctx, ("security", *key)):
        return False
    syslog.syslog(priority, f"QUBES-SNITCH SECURITY {safe_text(message, limit=300)}")
    try:
        notify.security_notify(message, ctx.CONFIG, ctx.NOTIFY_USER, ctx.NOTIFY_DISPLAY, ctx.NOTIFY_RUNTIME_DIR, ctx.NOTIFY_DBUS)
    except (ctx.subprocess.CalledProcessError, ctx.subprocess.TimeoutExpired, OSError) as error:
        fail_daemon(ctx, f"notify-send failed: {error}")
    return True


def fatal_security_alert(ctx, key, message):
    # Source identity is a hard security dependency; alert once, then make systemd mark the daemon failed
    security_alert(ctx, key, message, syslog.LOG_CRIT)
    fail_daemon(ctx, message)


def log_unparsed_packet(ctx):
    # Completely unparseable packets have no safe source/destination fields, so reject/log without prompting
    security_alert(ctx, ("malformed", "unparsed"), "REJECT malformed packet REASON=cannot extract prompt fields")


def log_malformed_packet(ctx, request):
    # Packets with bad headers get logged and rejected; never create a permanent rule from malformed data
    source = ctx.SOURCES_BY_IP.get(request["src"], request["src"])
    security_alert(
        ctx,
        ("malformed", source, request["proto"], request["malformed"]),
        f"REJECT malformed {request['proto']} SRC={source} IP={request['src']} DST={request['dst']} REASON={request['malformed']}",
    )


def unknown_source_alert(ctx, request):
    # A packet from an IP not mapped by dom0 cannot be safely attributed to a Qube, so it is never promptable
    security_alert(
        ctx,
        ("unknown-source", request["src"], request["dst"], request["proto"], str(request_port(request))),
        f"REJECT source IP unknown to Qubes SRC={request['src']} DST={request['dst']} PROTO={request['proto']} DPORT={request_port(request)}",
    )

