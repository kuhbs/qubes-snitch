# Pending prompt queue and CLI socket protocol for Qubes Snitch
# Current packets are rejected immediately; this queue stores questions for future traffic decisions

import itertools
import json
import syslog
import threading
from collections import OrderedDict

from qubes_snitch.packets import request_port, request_without_body


# Pending questions are RAM-only UI state; allow/reject YAML is written only after the CLI answers
PENDING_QUESTIONS = OrderedDict()
PENDING_PROMPT_IDS = {}
NEXT_PROMPT_ID = itertools.count(1)
PENDING_CONDITION = threading.Condition()


def question_key(request):
    # Deduplicate by source and target so repeated packets do not flood the prompt queue
    if request.get("kind") == "dns":
        return (request["source"], "dns", request["qtype"], request["qname"])
    return (request["source"], "net", request["dst"], request["proto"], request_port(request))


def queue_question(request, config, log_pending_reject, log_queue_full_reject, notify_queued=None):
    # The queue is bounded; if it fills, reject new questions until the user answers existing prompts
    prompt_request = request_without_body(request)
    key = question_key(prompt_request)
    queued = False
    full = False
    with PENDING_CONDITION:
        if key not in PENDING_QUESTIONS:
            if len(PENDING_QUESTIONS) >= config["pending_queue_size"]:
                full = True
            else:
                PENDING_QUESTIONS[key] = prompt_request
                PENDING_PROMPT_IDS[key] = next(NEXT_PROMPT_ID)
                queued = True
                PENDING_CONDITION.notify()
    if full:
        log_queue_full_reject(prompt_request)
        return "full"
    log_pending_reject(prompt_request)
    if queued and notify_queued:
        # Notify outside the queue lock so desktop notification work cannot block queue bookkeeping
        notify_queued(prompt_request)
    return "queued" if queued else "duplicate"


def next_pending_request():
    # Only the CLI waits for a question; NFQUEUE already returned accept or drop for the current packet
    with PENDING_CONDITION:
        while not PENDING_QUESTIONS:
            PENDING_CONDITION.wait()
        key, request = next(iter(PENDING_QUESTIONS.items()))
        queued_request = dict(request)
        # The daemon keeps this hidden prompt id to reject old CLI answers after Qubes reuses a numbered DispVM name
        queued_request["_prompt_id"] = PENDING_PROMPT_IDS[key]
        queued_request["remaining"] = len(PENDING_QUESTIONS) - 1
        return key, queued_request


def remove_pending_for_source(source):
    # Numbered DispVM prompts become unsafe when the disposable disappears
    with PENDING_CONDITION:
        for key in list(PENDING_QUESTIONS):
            if key[0] == source:
                del PENDING_QUESTIONS[key]
                PENDING_PROMPT_IDS.pop(key, None)


def discard_pending_decision(key, request):
    # Stale prompts discovered during CLI-side enrichment must not keep blocking the prompt queue
    with PENDING_CONDITION:
        if key in PENDING_QUESTIONS and PENDING_PROMPT_IDS.get(key) == request.get("_prompt_id"):
            del PENDING_QUESTIONS[key]
            PENDING_PROMPT_IDS.pop(key, None)


def save_pending_decision(key, request, decision, policy_lock, append_rule, load_nft):
    # Queue cleanup is authoritative; claim the prompt under policy lock so source cleanup cannot race rule writes
    with policy_lock:
        with PENDING_CONDITION:
            if key not in PENDING_QUESTIONS or PENDING_PROMPT_IDS.get(key) != request.get("_prompt_id"):
                syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH ignore stale CLI decision for vanished prompt: {key}")
                return
            del PENDING_QUESTIONS[key]
            PENDING_PROMPT_IDS.pop(key, None)
        append_rule(request, decision)
        load_nft()


def handle_cli_connection(conn, policy_lock, append_rule, load_nft, enrich_request=None):
    # Protocol contract: daemon sends one JSON line, CLI sends one answer line, then the connection closes
    key, request = next_pending_request()
    if enrich_request:
        enriched = enrich_request(dict(request))
        if enriched is None:
            discard_pending_decision(key, request)
            return
        request = enriched
    try:
        with conn:
            conn.sendall(json.dumps(request, sort_keys=True).encode("utf-8") + b"\n")
            decision = conn.makefile("r", encoding="utf-8").readline().strip()
    except OSError as error:
        syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH keep pending request after CLI error: {error}")
        return
    if decision not in ("allow", "reject"):
        # Invalid or empty answers are ignored so accidental terminal exits do not create firewall rules
        syslog.syslog(syslog.LOG_INFO, f"QUBES-SNITCH keep pending request after invalid CLI decision: {decision!r}")
        return
    save_pending_decision(key, request, decision, policy_lock, append_rule, load_nft)
