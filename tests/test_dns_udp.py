# Purpose: regression tests for UDP DNS parsing and domain-policy behavior
# Scope: keeps DNS-specific qname/qtype decisions separate from normal IP:port packet tests
import unittest
import types
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from snitch_testlib import load_snitchd


class DnsUdpTests(unittest.TestCase):
    # DNS tests stay together because DNS has both transport-flow and domain-question behavior
    def test_udp_dns_query_becomes_domain_decision_prompt(self):
        # DNS qname/qtype prompts should be created from normal UDP DNS questions
        snitchd = load_snitchd()
        request = {"source": "app-signal", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-a"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns")
        self.assertEqual(request["qname"], "example.com")
        self.assertEqual(request["qtype"], "A")
        self.assertEqual(snitchd.notify.request_text(request), "app-signal DNS A example.com")

    def test_oversize_dns_query_is_rejected_before_parse(self):
        snitchd = load_snitchd()
        request = {"source": "app-signal", "proto": "udp", "sport": 53000, "dport": 53, "body": b"x" * 1233}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns-error")
        self.assertEqual(request["dns_error"], "oversize-body")

    def test_multi_question_dns_query_is_logged_and_dropped(self):
        # Normal DNS QUERY packets must have exactly one question; extra questions could hide unreviewed domains
        snitchd = load_snitchd()
        events = []
        packet = type("Packet", (), {
            "get_payload": lambda self: b"payload",
            "set_payload": lambda self, payload: events.append(("set_payload", payload)),
            "accept": lambda self: events.append(("accept", None)),
            "drop": lambda self: events.append(("drop", None)),
        })()
        snitchd.SOURCES_BY_IP = {"10.137.50.20": "app-signal"}
        snitchd.SOURCE_LABELS = {"app-signal": "green"}
        snitchd.RULES = {"app-signal": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": 53, "action": "allow"}], "dns": []}}
        snitchd.parse_packet = lambda _payload: {"src": "10.137.50.20", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-multi"}
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))
        snitchd.notify.security_notify = lambda message, *_args: events.append(("notify", message))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertIn(("syslog", snitchd.syslog.LOG_WARNING, "QUBES-SNITCH SECURITY REJECT malformed DNS SRC=app-signal IP=10.137.50.20 DST=10.139.1.1 REASON=multi-question"), events)
        self.assertEqual([event[0] for event in events].count("set_payload"), 0)
        self.assertEqual(events[-1], ("drop", None))

    def test_aaaa_dns_query_gets_refused_without_prompt_or_rule(self):
        # IPv6 is unsupported, so AAAA questions get a fast DNS REFUSED response without persistent policy
        snitchd = load_snitchd()
        events = []
        packet = type("Packet", (), {
            "get_payload": lambda self: b"payload",
            "set_payload": lambda self, payload: events.append(("set_payload", payload)),
            "accept": lambda self: events.append(("accept", None)),
            "drop": lambda self: events.append(("drop", None)),
        })()
        snitchd.SOURCES_BY_IP = {"10.137.50.20": "app-signal"}
        snitchd.SOURCE_LABELS = {"app-signal": "green"}
        snitchd.RULES = {"app-signal": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": 53, "action": "allow"}], "dns": []}}
        snitchd.parse_packet = lambda _payload: {"src": "10.137.50.20", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-aaaa"}
        snitchd.queue_question = lambda request: events.append(("queue", request))
        fake_socket = types.SimpleNamespace(
            setsockopt=lambda *_args: None,
            sendto=lambda payload, target: events.append(("sendto", payload, target)),
            close=lambda: events.append(("close", None)),
        )
        original_socket = snitchd.socket.socket
        snitchd.socket.socket = lambda *_args: fake_socket
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        try:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)
        finally:
            snitchd.socket.socket = original_socket

        self.assertIn(("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH app-signal reject DNS SRC=10.137.50.20 DST=10.139.1.1 QTYPE=AAAA QNAME=example.com REASON=unsupported"), events)
        self.assertNotIn("queue", [event[0] for event in events])
        self.assertEqual([event[0] for event in events].count("set_payload"), 0)
        sent = [event for event in events if event[0] == "sendto"][0]
        self.assertIn(b"dns-response-rcode-5-answers-0", sent[1])
        self.assertEqual(sent[2], ("10.137.50.20", 0))
        self.assertEqual(events[-1], ("drop", None))

    def test_ip6_arpa_ptr_query_gets_refused_without_prompt_or_rule(self):
        # IPv6 reverse DNS names are IPv6 policy surface, so Snitch refuses them like AAAA
        snitchd = load_snitchd()
        request = {"source": "app-signal", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-ip6-ptr"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns-error")
        self.assertEqual(request["dns_error"], "unsupported-qname")

    def test_manual_ip6_arpa_ptr_rule_is_rejected(self):
        # Manual YAML must reject the same IPv6 reverse-DNS policy that live prompts reject
        snitchd = load_snitchd()
        data = {"rules4": [], "dns": [{"qname": "8.b.d.0.1.0.0.2.ip6.arpa", "qtype": "PTR", "action": "allow"}]}

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("browser.yml"), data)

    def test_dns_decision_is_persistent_yaml_rule(self):
        # A CLI DNS decision must persist as a dns: entry, not as a UDP/53 flow rule
        snitchd = load_snitchd()
        with TemporaryDirectory() as td:
            snitchd.RULES_DIR = Path(td)
            snitchd.RULES = {}
            request = {"kind": "dns", "source": "app-signal", "qname": "example.com", "qtype": "A"}

            snitchd.policy_runtime.append_rule(snitchd.context(), request, "allow")

            data = yaml.safe_load((Path(td) / "app-signal.yml").read_text())
            self.assertEqual(data, {"rules4": [], "dns": [{"qname": "example.com", "qtype": "A", "action": "allow"}]})
            self.assertEqual(snitchd.policy_runtime.matching_action(snitchd.context(), request), "allow")

    def test_srv_style_dns_decision_survives_reload_validation(self):
        # The daemon must not write DNS decisions that its own startup validator rejects later
        snitchd = load_snitchd()
        with TemporaryDirectory() as td:
            snitchd.RULES_DIR = Path(td)
            snitchd.RULES = {}
            request = {"kind": "dns", "source": "browser", "qname": "_http._tcp.deb.debian.org", "qtype": "SRV"}

            snitchd.policy_runtime.append_rule(snitchd.context(), request, "allow")

            data = snitchd.config.load_rules(Path(td))
            self.assertEqual(data["browser"]["dns"][0]["qname"], "_http._tcp.deb.debian.org")

    def test_srv_dns_query_requires_normal_dotted_suffix(self):
        # SRV permits _service._proto only before the same multi-label suffix required for normal qnames
        snitchd = load_snitchd()
        request = {"source": "app-signal", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-srv-single-label"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns-error")
        self.assertEqual(request["dns_error"], "unsupported-qname")

    def test_rejected_dns_answer_uses_refused_without_loopback_record(self):
        # Policy rejects should tell the client DNS refused instead of redirecting it to localhost
        snitchd = load_snitchd()
        request = {"body": b"query-a", "qtype": "A", "src": "10.137.50.20", "dst": "10.139.1.1", "sport": 53000, "dport": 53}

        payload = snitchd.dns_reject_payload(b"payload", request)

        self.assertIn(b"dns-response-rcode-5-answers-0", payload)
        self.assertNotIn(b"127.0.0.1", payload)

    def test_allowed_a_rule_lazily_refreshes_display_hint(self):
        # DNS hints refresh in the CLI thread so NFQUEUE packet verdicts never wait on resolver I/O
        snitchd = load_snitchd()
        with TemporaryDirectory() as td:
            class FakeAnswers(list):
                rrset = type("RRSet", (), {"ttl": 120})()
            answer = type("Answer", (), {"to_text": lambda self: "93.184.216.34"})()
            snitchd.dns.resolver.resolve = lambda qname, qtype, lifetime: FakeAnswers([answer])
            snitchd.time.monotonic = lambda: 100.0
            snitchd.RULES_DIR = Path(td)
            snitchd.RULES = {}
            dns_request = {"kind": "dns", "source": "app-signal", "qname": "example.com", "qtype": "A"}
            flow_request = {"source": "app-signal", "dst": "93.184.216.34", "proto": "tcp", "dport": 443, "host": None}

            snitchd.policy_runtime.append_rule(snitchd.context(), dns_request, "allow")
            enriched = snitchd.dns_cache_runtime.enrich_prompt_request(snitchd.context(), flow_request)

            self.assertEqual(enriched["host"], "DNS example.com")

    def test_allowed_a_rule_refresh_checks_later_rules(self):
        # Display hints must not depend on YAML rule order
        snitchd = load_snitchd()
        class FakeAnswers(list):
            rrset = type("RRSet", (), {"ttl": 120})()
        answers = {
            "old1.example": [],
            "old2.example": [],
            "old3.example": [],
            "updates.signal.org": [type("Answer", (), {"to_text": lambda self: "104.18.3.166"})()],
        }
        calls = []
        def fake_resolve(qname, qtype, lifetime):
            calls.append((qname, qtype))
            if qtype == "PTR":
                raise RuntimeError("no fake PTR")
            return FakeAnswers(answers[qname])
        snitchd.dns.resolver.resolve = fake_resolve
        snitchd.time.monotonic = lambda: 100.0
        snitchd.RULES = {"app-signal": {"ip": [], "dns": [
            {"qname": "old1.example", "qtype": "A", "action": "allow"},
            {"qname": "old2.example", "qtype": "A", "action": "allow"},
            {"qname": "old3.example", "qtype": "A", "action": "allow"},
            {"qname": "updates.signal.org", "qtype": "A", "action": "allow"},
        ]}}
        flow_request = {"source": "app-signal", "dst": "104.18.3.166", "proto": "tcp", "dport": 443, "host": None}

        enriched = snitchd.dns_cache_runtime.enrich_prompt_request(snitchd.context(), flow_request)

        self.assertEqual(enriched["host"], "DNS updates.signal.org")
        self.assertIn(("updates.signal.org", "A"), calls)

    def test_stale_dns_refresh_uses_configured_worker_limit(self):
        # Missing or stale hint names are refreshed together, with config bounding resolver concurrency
        snitchd = load_snitchd()
        class FakeAnswers(list):
            rrset = type("RRSet", (), {"ttl": 120})()
        class FakeFuture:
            def __init__(self, result):
                self._result = result
            def result(self):
                return self._result
        class FakeExecutor:
            def __init__(self, max_workers):
                worker_counts.append(max_workers)
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def submit(self, fn, *args):
                submitted.append(args)
                return FakeFuture(fn(*args))
        worker_counts = []
        submitted = []
        target = "target39.example"
        rules = [{"qname": f"target{i}.example", "qtype": "A", "action": "allow"} for i in range(40)]
        answers = {rule["qname"]: [] for rule in rules}
        answers[target] = [type("Answer", (), {"to_text": lambda self: "104.18.3.166"})()]
        def fake_resolve(qname, qtype, lifetime):
            if qtype == "PTR":
                raise RuntimeError("no fake PTR")
            return FakeAnswers(answers[qname])
        old_executor = snitchd.dns_cache_runtime.ThreadPoolExecutor
        snitchd.dns_cache_runtime.ThreadPoolExecutor = FakeExecutor
        snitchd.dns.resolver.resolve = fake_resolve
        snitchd.time.monotonic = lambda: 100.0
        snitchd.CONFIG["dns_cache_refresh_workers"] = 32
        snitchd.RULES = {"app-signal": {"ip": [], "dns": rules}}
        flow_request = {"source": "app-signal", "dst": "104.18.3.166", "proto": "tcp", "dport": 443, "host": None}

        try:
            enriched = snitchd.dns_cache_runtime.enrich_prompt_request(snitchd.context(), flow_request)
        finally:
            snitchd.dns_cache_runtime.ThreadPoolExecutor = old_executor

        self.assertEqual(enriched["host"], f"DNS {target}")
        self.assertEqual(worker_counts, [32])
        self.assertEqual(len(submitted), 40)

    def test_allowed_non_a_rule_does_not_create_ip_display_hint(self):
        # MX/TXT/SRV/etc can be policy-managed, but display hints stay limited to A/CNAME endpoint lookups
        snitchd = load_snitchd()
        with TemporaryDirectory() as td:
            calls = []
            def fake_resolve(_qname, qtype, lifetime):
                calls.append(qtype)
                raise RuntimeError("no fake resolver answer")
            snitchd.dns.resolver.resolve = fake_resolve
            snitchd.RULES_DIR = Path(td)
            snitchd.RULES = {}
            dns_request = {"kind": "dns", "source": "app-signal", "qname": "example.com", "qtype": "MX"}
            flow_request = {"source": "app-signal", "dst": "93.184.216.34", "proto": "tcp", "dport": 25, "host": None}

            snitchd.policy_runtime.append_rule(snitchd.context(), dns_request, "allow")
            enriched = snitchd.dns_cache_runtime.enrich_prompt_request(snitchd.context(), flow_request)

            self.assertEqual(snitchd.DNS_RESPONSE_CACHE, {})
            self.assertNotIn("MX", calls)
            self.assertIsNone(enriched.get("host"))

    def test_nft_checks_source_dns_queue_before_established_accept(self):
        # Known-source DNS queries must enter the source chain before established traffic is accepted
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [{"ptr": "dns", "dest": "10.139.1.1", "proto": "udp", "port": "domain", "action": "allow"}], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        generic_accept = "ip daddr 10.137.0.42 ct state established,related ct direction reply accept"
        self.assertLess(nft.index("ip saddr 10.137.0.42 udp dport 53 jump"), nft.index(generic_accept))
        self.assertNotIn("  meta nfproto ipv4 ct state established,related ct direction reply accept\n  ip saddr", nft)

    def test_fail_closed_nft_has_no_established_bypass(self):
        # Startup fallback must not allow established traffic before dom0 source discovery succeeds
        snitchd = load_snitchd()
        nft = snitchd.nft.render_fail_closed_nft(snitchd.CONFIG, "qubes_snitch_test", 50)

        self.assertIn("queue num 50", nft)
        self.assertNotIn("ct state established,related ct direction reply accept", nft)
        self.assertNotIn("udp sport 53 queue", nft)

    def test_outgoing_udp53_is_queued_before_established_accept(self):
        # Reused resolver sockets can be conntrack-established, so UDP/53 must hit domain policy first
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        generic_accept = "ip daddr 10.137.0.42 ct state established,related ct direction reply accept"
        self.assertLess(nft.index("ip saddr 10.137.0.42 udp dport 53 jump"), nft.index(generic_accept))

    def test_broad_udp_allow_still_queues_dns_transport(self):
        # A broad UDP allow still has to queue DNS so domain policy cannot be bypassed
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [{"ptr": "dns", "dest": "any", "proto": "udp", "port": "any", "action": "allow"}], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        self.assertLess(nft.index("udp dport 53 queue"), nft.index("  meta nfproto ipv4 meta l4proto udp accept"))

    def test_dns_wildcard_rule_matches_domain_suffix(self):
        # Wildcard DNS rules match subdomains on a label boundary
        snitchd = load_snitchd()
        setattr(snitchd, "RULES", {"app-signal": {"ip": [], "dns": [{"qname": "*.example.com", "qtype": "A", "action": "allow"}]}})
        request = {"kind": "dns", "source": "app-signal", "qname": "api.example.com", "qtype": "A"}

        self.assertEqual(snitchd.policy_runtime.matching_action(snitchd.context(), request), "allow")

    def test_dns_wildcard_rule_does_not_cross_suffix_boundary(self):
        # Wildcard DNS rules must not match a string that merely ends with the same characters
        snitchd = load_snitchd()
        setattr(snitchd, "RULES", {"app-signal": {"ip": [], "dns": [{"qname": "*.example.com", "qtype": "A", "action": "allow"}]}})
        request = {"kind": "dns", "source": "app-signal", "qname": "badexample.com", "qtype": "A"}

        self.assertIsNone(snitchd.policy_runtime.matching_action(snitchd.context(), request))

    def test_mx_dns_query_is_supported_policy_prompt(self):
        # Mail lookup types are supported by the whitelist and become DNS prompts
        snitchd = load_snitchd()
        request = {"source": "mail", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-mx"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns")
        self.assertEqual(request["qtype"], "MX")
        self.assertEqual(request["qname"], "example.com")

    def test_non_in_and_any_dns_queries_are_unsupported(self):
        # Unsupported DNS never reaches policy or YAML
        snitchd = load_snitchd()
        for payload, reason in ((b"query-ch", "unsupported-qclass"), (b"query-any", "unsupported-qtype"), (b"query-additional", "unexpected-sections")):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))

            self.assertEqual(request["kind"], "dns-error")
            self.assertEqual(request["dns_error"], reason)

    def test_live_dns_rejects_non_common_ascii_qnames(self):
        # Live VM questions must not turn wildcard, root, escaped, or invalid-label names into policy YAML
        snitchd = load_snitchd()
        for payload in (b"query-wildcard", b"query-root", b"query-bad-leading", b"query-bad-escape"):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))

            self.assertEqual(request["kind"], "dns-error")
            self.assertEqual(request["dns_error"], "unsupported-qname")


    def test_live_srv_underscore_qname_is_supported(self):
        # SRV owner names legitimately use _service._proto labels and must match manual YAML validation
        snitchd = load_snitchd()
        request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-srv"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns")
        self.assertEqual(request["qname"], "_http._tcp.example.com")
        self.assertEqual(request["qtype"], "SRV")

    def test_live_dns_rejects_punycode_idn_labels(self):
        # The no-IDN model rejects xn-- labels before they can become lookalike policy
        snitchd = load_snitchd()
        request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-xn"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns-error")
        self.assertEqual(request["dns_error"], "unsupported-qname")

    def test_manual_dns_wildcard_does_not_match_apex(self):
        # Manual *.example.com policy is for subdomains only, not the bare example.com apex
        snitchd = load_snitchd()
        setattr(snitchd, "RULES", {"app-signal": {"ip": [], "dns": [{"qname": "*.example.com", "qtype": "A", "action": "allow"}]}})
        request = {"kind": "dns", "source": "app-signal", "qname": "example.com", "qtype": "A"}

        self.assertIsNone(snitchd.policy_runtime.matching_action(snitchd.context(), request))

    def test_edns_options_are_allowed_inside_one_opt_record(self):
        # dnspython exposes EDNS options, not OPT pseudo-record count; multiple options are valid
        snitchd = load_snitchd()
        for payload in (b"query-edns", b"query-two-edns"):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))
            self.assertEqual(request["kind"], "dns")

    def test_dns_queries_with_response_only_flags_or_rcode_are_rejected(self):
        # Client DNS prompts only support normal QUERY packets; response-only flags and RCODE are malformed
        snitchd = load_snitchd()
        for payload, reason in ((b"query-ra-flag", "non-query-flags"), (b"query-rcode-refused", "non-query-rcode")):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))

            self.assertEqual(request["kind"], "dns-error")
            self.assertEqual(request["dns_error"], reason)

    def test_dns_query_with_rd_flag_is_still_normal(self):
        # Recursive-desired is the one common client QUERY flag Snitch accepts
        snitchd = load_snitchd()
        request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-rd-flag"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns")
        self.assertEqual(request["qname"], "example.com")

    def test_dns_query_with_unsupported_edns_version_is_rejected(self):
        # EDNS versions other than 0 are not normal client queries Snitch can safely treat as domain policy
        snitchd = load_snitchd()
        request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-edns-v1"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns-error")
        self.assertEqual(request["dns_error"], "unsupported-edns-version")

    def test_dnssec_query_flags_are_still_normal_client_queries(self):
        # DNSSEC-aware clients may set AD or CD on ordinary QUERY packets
        snitchd = load_snitchd()
        for payload in (b"query-ad-flag", b"query-cd-flag"):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))

            self.assertEqual(request["kind"], "dns")
            self.assertEqual(request["qname"], "example.com")
            self.assertEqual(request["qtype"], "A")

    def test_unsupported_edns_version_full_handler_rejects_without_crashing(self):
        # Unsupported EDNS with a question needs qname/qtype for the REFUSED/log path
        snitchd = load_snitchd()
        events = []
        packet = type("Packet", (), {
            "get_payload": lambda self: b"payload",
            "accept": lambda self: events.append(("accept", None)),
            "drop": lambda self: events.append(("drop", None)),
        })()
        snitchd.SOURCES_BY_IP = {"10.137.50.20": "app-signal"}
        snitchd.SOURCE_LABELS = {"app-signal": "green"}
        snitchd.RULES = {"app-signal": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": "53", "action": "allow"}], "dns": []}}
        snitchd.parse_packet = lambda _payload: {"src": "10.137.50.20", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-edns-v1"}
        snitchd.dns_reject_payload = lambda _payload, request: events.append(("reject-payload", request["qtype"], request["qname"])) or b"reject"
        fake_socket = types.SimpleNamespace(setsockopt=lambda *_args: None, sendto=lambda payload, target: events.append(("sendto", payload, target)), close=lambda: None)
        original_socket = snitchd.socket.socket
        snitchd.socket.socket = lambda *_args: fake_socket
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        try:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)
        finally:
            snitchd.socket.socket = original_socket

        self.assertIn(("reject-payload", "A", "example.com"), events)
        self.assertEqual(events[-1], ("drop", None))

    def test_edns_extended_rcode_and_reserved_flags_are_rejected(self):
        # EDNS0 is okay, but extended errors and reserved EDNS Z flags are not normal client queries
        snitchd = load_snitchd()
        for payload, reason in ((b"query-edns-extended-rcode", "non-query-rcode"), (b"query-edns-reserved-flag", "unsupported-edns-flags")):
            request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": payload}

            self.assertTrue(snitchd.add_dns_query_fields(request))

            self.assertEqual(request["kind"], "dns-error")
            self.assertEqual(request["dns_error"], reason)

    def test_edns_do_flag_is_still_normal(self):
        # DNSSEC OK is the one supported EDNS flag for ordinary client queries
        snitchd = load_snitchd()
        request = {"source": "browser", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-edns-do-flag"}

        self.assertTrue(snitchd.add_dns_query_fields(request))

        self.assertEqual(request["kind"], "dns")
        self.assertEqual(request["qname"], "example.com")
