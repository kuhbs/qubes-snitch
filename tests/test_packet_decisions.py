# Purpose: regression tests for daemon packet-handling decisions
# Scope: uses fake packet objects so decisions can be tested without root, nftables, or NFQUEUE
import socket
import struct
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from snitch_testlib import load_snitchd


class PacketDecisionTests(unittest.TestCase):
    # Packet tests focus on verdicts, queueing, malformed handling, and source mapping
    def test_first_dns_packet_prompts_for_dns_transport_flow(self):
        # First UDP/53 traffic asks about the resolver IP/port before looking inside the DNS question
        snitchd = load_snitchd()
        captured = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: None, drop=lambda: None)
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-a"})
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: captured.append(snitchd.request_without_body(request)))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(captured[0], {
            "src": "10.137.0.42",
            "source": "browser",
            "source_label": "blue",
            "display_source": "browser",
            "dst": "10.139.1.1",
            "proto": "udp",
            "sport": 53000,
            "dport": 53,
            "host": None,
        })

    def test_rejected_dns_domain_sends_refused_reply_and_drops_query(self):
        # A rejected DNS name sends a fresh REFUSED reply, then drops the original forwarded query
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(
            get_payload=lambda: b"payload",
            set_payload=lambda payload: events.append(("set_payload", payload)),
            accept=lambda: events.append(("accept", None)),
            drop=lambda: events.append(("drop", None)),
        )
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": 53, "action": "allow"}], "dns": [{"qname": "example.com", "qtype": "A", "action": "reject"}]}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-a"})
        setattr(snitchd, "dns_reject_payload", lambda payload, request: b"local-dns-reject")
        fake_socket = types.SimpleNamespace(
            setsockopt=lambda *args: events.append(("setsockopt", args)),
            sendto=lambda payload, target: events.append(("sendto", payload, target)),
            close=lambda: events.append(("close", None)),
        )
        original_socket = snitchd.socket.socket
        setattr(snitchd.socket, "socket", lambda family, socktype, proto: events.append(("socket", family, socktype, proto)) or fake_socket)
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        try:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)
        finally:
            snitchd.socket.socket = original_socket

        self.assertEqual(events, [
            ("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH browser reject DNS SRC=10.137.0.42 DST=10.139.1.1 QTYPE=A QNAME=example.com REASON=rule"),
            ("socket", snitchd.socket.AF_INET, snitchd.socket.SOCK_RAW, snitchd.socket.IPPROTO_RAW),
            ("setsockopt", (snitchd.socket.IPPROTO_IP, snitchd.socket.IP_HDRINCL, 1)),
            ("sendto", b"local-dns-reject", ("10.137.0.42", 53000)),
            ("close", None),
            ("drop", None),
        ])

    def test_new_dns_domain_prompt_silently_drops_current_query(self):
        # Unknown DNS names are queued, but the current UDP packet is not answered with policy REFUSED
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(
            get_payload=lambda: b"payload",
            set_payload=lambda payload: events.append(("set_payload", payload)),
            accept=lambda: events.append(("accept", None)),
            drop=lambda: events.append(("drop", None)),
        )
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": 53, "action": "allow"}], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-a"})
        setattr(snitchd, "dns_reject_payload", lambda payload, request: events.append(("dns-refused", request)) or b"local-dns-reject")
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(events, [
            ("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH browser reject pending DNS QTYPE=A QNAME=example.com"),
            ("drop", None),
        ])

    def test_udp_source_port_53_to_client_is_normal_established_traffic_now(self):
        # Resolver replies are established traffic; reply traffic to known sources accepts before queue 50
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        self.assertNotIn("udp sport 53 queue", nft)
        self.assertIn("ip daddr 10.137.0.42 ct state established,related ct direction reply accept", nft)

    def test_stale_source_prompt_is_not_queued_after_cleanup(self):
        # A source can disappear after packet enrichment but before queueing; stale prompts must not be recreated
        snitchd = load_snitchd()
        events = []
        request = {"src": "10.137.0.55", "source": "disp1234", "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "host": None}
        snitchd.SOURCES_BY_NAME = {"disp1234": ["10.137.0.56"]}
        snitchd.SOURCES_BY_IP = {"10.137.0.56": "disp1234"}
        snitchd.queue.PENDING_QUESTIONS.clear()
        snitchd.alerts_runtime.notify_prompt = lambda _ctx, queued: events.append(("notify", queued))
        snitchd.alerts_runtime.log_pending_reject = lambda _ctx, queued: events.append(("log", queued))
        snitchd.alerts_runtime.log_queue_full_reject = lambda _ctx, rejected: events.append(("queue-full", rejected))
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        snitchd.packet_handlers.queue_prompt(snitchd.context(), request)

        self.assertEqual(snitchd.queue.PENDING_QUESTIONS, {})
        self.assertEqual(events, [("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH ignore stale prompt for vanished source: disp1234")])

    def test_saved_rule_race_does_not_queue_stale_flow_prompt(self):
        # A CLI answer can save policy after the first packet match check; recheck under the queue lock before prompting
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(accept=lambda: events.append("accept"), drop=lambda: events.append("reject"))
        request = {"src": "10.137.0.42", "source": "browser", "dst": "1.2.3.4", "proto": "tcp", "sport": 50000, "dport": 443, "host": None}
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "RULES", {"browser": {"ip": [], "dns": []}})
        snitchd.queue.PENDING_QUESTIONS.clear()
        original_matching_action = snitchd.policy_runtime.matching_action

        def save_rule_after_first_match(_ctx, _request):
            setattr(snitchd, "RULES", {"browser": {"ip": [{"ptr": "raced", "dest": "1.2.3.4", "proto": "tcp", "port": "443", "action": "allow"}], "dns": []}})
            return None

        snitchd.policy_runtime.matching_action = save_rule_after_first_match
        try:
            snitchd.packet_handlers.handle_flow_packet(snitchd.context(), packet, request)
        finally:
            snitchd.policy_runtime.matching_action = original_matching_action

        self.assertEqual(events, ["accept"])
        self.assertEqual(snitchd.queue.PENDING_QUESTIONS, {})

    def test_udp_source_port_53_to_non_dns_port_is_not_reply_bypass(self):
        # A protected VM using source port 53 is still normal traffic unless it is resolver -> protected VM reply traffic
        snitchd = load_snitchd()
        captured = []
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("reject"))
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "9.9.9.9", "proto": "udp", "sport": 53, "dport": 443, "body": b""})
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: captured.append(snitchd.request_without_body(request)))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(events, ["reject"])
        self.assertEqual(captured[0]["source"], "browser")
        self.assertEqual(captured[0]["sport"], 53)
        self.assertEqual(captured[0]["dport"], 443)

    def test_udp_source_and_dest_port_53_is_dns_query_not_reply(self):
        # DNS query policy wins if both ports are 53, preventing source-port tricks from bypassing qname rules
        snitchd = load_snitchd()
        captured = []
        events = []
        packet = types.SimpleNamespace(
            get_payload=lambda: b"payload",
            set_payload=lambda payload: events.append(("set_payload", payload)),
            accept=lambda: events.append("accept"),
            drop=lambda: events.append("reject"),
        )
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [{"ptr": "resolver", "dest": "9.9.9.9", "proto": "udp", "port": 53, "action": "allow"}], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "9.9.9.9", "proto": "udp", "sport": 53, "dport": 53, "body": b"query-a"})
        setattr(snitchd, "dns_reject_payload", lambda payload, request: b"local-dns-reject")
        fake_socket = types.SimpleNamespace(setsockopt=lambda *_args: None, sendto=lambda *_args: events.append("sendto"), close=lambda: None)
        original_socket = snitchd.socket.socket
        setattr(snitchd.socket, "socket", lambda *_args: fake_socket)
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: captured.append(snitchd.request_without_body(request)))
        snitchd.syslog.syslog = lambda *_args: None

        try:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)
        finally:
            snitchd.socket.socket = original_socket

        self.assertEqual(captured[0]["kind"], "dns")
        self.assertEqual(captured[0]["qname"], "example.com")
        self.assertNotIn("sendto", events)
        self.assertIn("reject", events)

    def test_unknown_source_refreshes_before_failing_daemon(self):
        # Unknown source IP gets one dom0 refresh before fail-closed
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("drop"))
        setattr(snitchd, "SOURCES_BY_IP", {})
        setattr(snitchd, "SOURCES_BY_NAME", {})
        setattr(snitchd, "SOURCE_LABELS", {})
        setattr(snitchd, "RULES", {})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.99", "dst": "1.2.3.4", "proto": "tcp", "sport": 50000, "dport": 443, "body": b""})
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: events.append(("queue", request)))
        setattr(snitchd.sources_runtime, "refresh_sources_and_nft", lambda _ctx, force=False: events.append(("refresh", force)))
        setattr(snitchd.alerts_runtime, "fatal_security_alert", lambda _ctx, key, message: (_ for _ in ()).throw(SystemExit((key, message))))

        with self.assertRaises(SystemExit) as caught:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(caught.exception.code[0], ("unknown-source", "10.137.0.99"))
        self.assertEqual(events, [("refresh", True)])

    def test_unknown_source_known_after_refresh_rejects_current_packet(self):
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("reject"))
        setattr(snitchd, "SOURCES_BY_IP", {})
        setattr(snitchd, "SOURCES_BY_NAME", {})
        setattr(snitchd, "SOURCE_LABELS", {})
        setattr(snitchd, "RULES", {})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.99", "dst": "1.2.3.4", "proto": "tcp", "sport": 50000, "dport": 443, "body": b""})
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: events.append(("queue", request)))
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        def refresh(_ctx, force=False):
            events.append(("refresh", force))
            snitchd.SOURCES_BY_IP = {"10.137.0.99": "browser"}
            snitchd.SOURCES_BY_NAME = {"browser": ["10.137.0.99"]}
            snitchd.RULES = {"browser": {"ip": [], "dns": []}}

        setattr(snitchd.sources_runtime, "refresh_sources_and_nft", refresh)

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(events, [
            ("refresh", True),
            ("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH browser reject NET DST=1.2.3.4 PROTO=tcp DPORT=443 REASON=source-refresh"),
            "reject",
        ])


    def test_unknown_source_fails_daemon_without_creating_raw_ip_rule(self):
        # Unknown source IPs are not recoverable packet-path events; fail closed instead of writing raw-IP policy
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            captured = []
            packet = type("Packet", (), {
                "get_payload": lambda self: b"payload",
                "accept": lambda self: captured.append("accept"),
                "drop": lambda self: captured.append("drop"),
            })()
            setattr(snitchd, "RULES_DIR", Path(tmp))
            setattr(snitchd, "SOURCES_BY_IP", {})
            setattr(snitchd, "SOURCE_LABELS", {})
            setattr(snitchd, "RULES", {})
            setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.99", "dst": "1.2.3.4", "proto": "tcp", "sport": 50000, "dport": 443, "body": b""})
            setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: captured.append(snitchd.request_without_body(request)))
            setattr(snitchd.sources_runtime, "refresh_sources_and_nft", lambda _ctx, force=False: None)

            with self.assertRaises(SystemExit):
                snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

            self.assertFalse((Path(tmp) / "10.137.0.99.yml").exists())
            self.assertEqual(captured, [])

    def test_malformed_packet_from_unknown_source_fails_daemon(self):
        # Source identity failures win before malformed packet handling because unknown VM traffic is a hard stop
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("drop"))
        setattr(snitchd, "SOURCES_BY_IP", {})
        setattr(snitchd, "SOURCES_BY_NAME", {})
        setattr(snitchd, "SOURCE_LABELS", {})
        setattr(snitchd, "RULES", {})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.99", "dst": "1.2.3.4", "proto": "tcp", "sport": 50000, "dport": 443, "body": b"", "malformed": "bad tcp"})
        setattr(snitchd.sources_runtime, "refresh_sources_and_nft", lambda _ctx, force=False: events.append(("refresh", force)))
        setattr(snitchd.alerts_runtime, "fatal_security_alert", lambda _ctx, key, message: (_ for _ in ()).throw(SystemExit((key, message))))
        snitchd.syslog.syslog = lambda *args: events.append(("syslog", *args))

        with self.assertRaises(SystemExit) as caught:
            snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(caught.exception.code[0], ("unknown-source", "10.137.0.99"))
        self.assertEqual(events, [("refresh", True)])


    def test_refused_dns_send_failure_still_drops_original_query(self):
        # Raw REFUSED delivery failure must not escape the NFQUEUE callback or leave the query without a verdict
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(drop=lambda: events.append("drop"), accept=lambda: events.append("accept"))
        request = {"src": "10.137.50.20", "dst": "10.139.1.1", "source": "browser", "qname": "example.com", "qtype": "A"}
        snitchd.packet_handlers.send_dns_refused = lambda *_args: (_ for _ in ()).throw(OSError("raw send failed"))
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        snitchd.packet_handlers.answer_rejected_dns(snitchd.context(), packet, b"payload", request, "rule")

        self.assertIn("drop", events)
        self.assertTrue(any(event[0] == "syslog" and "could not send DNS REFUSED" in event[2] for event in events if isinstance(event, tuple)))

    def test_ipv4_reserved_flag_and_tcp_udp_source_port_zero_are_malformed(self):
        # Invalid IPv4 flags and source port zero must never become promptable traffic
        snitchd = load_snitchd()
        import struct, socket

        def ipv4_packet(proto, sport, dport, fragment_field=0):
            body = struct.pack("!HHHH", sport, dport, 8, 0) if proto == 17 else struct.pack("!HHLLBBHHH", sport, dport, 0, 0, 5 << 4, 0, 0, 0, 0)
            total = 20 + len(body)
            header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, fragment_field, 64, proto, 0, socket.inet_aton("10.137.0.2"), socket.inet_aton("1.2.3.4"))
            return header + body

        self.assertEqual(snitchd.parse_packet(ipv4_packet(6, 1234, 443, 0x8000))["malformed"], "ipv4 reserved flag set")
        self.assertEqual(snitchd.parse_packet(ipv4_packet(6, 0, 443))["malformed"], "tcp/udp source port 0")
        self.assertEqual(snitchd.parse_packet(ipv4_packet(17, 0, 53))["malformed"], "tcp/udp source port 0")

    def test_unparseable_packet_is_logged_and_not_prompted(self):
        # Totally unparseable packets must log/drop without entering the user prompt queue
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"short", accept=lambda: events.append("accept"), drop=lambda: events.append("drop"))
        snitchd.syslog.syslog = lambda *args: events.append(("syslog", *args))
        snitchd.notify.security_notify = lambda message, *_args: events.append(("notify", message))
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: events.append(("queue", request)))
        setattr(snitchd, "LOG_BUCKETS", {})

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(events, [
            ("syslog", snitchd.syslog.LOG_WARNING, "QUBES-SNITCH SECURITY REJECT malformed packet REASON=cannot extract prompt fields"),
            ("notify", "REJECT malformed packet REASON=cannot extract prompt fields"),
            "drop",
        ])

    def test_malformed_ipv4_and_udp_headers_do_not_become_prompts(self):
        # Truncated or invalid headers must not create broad allow/reject YAML rules
        snitchd = load_snitchd()
        bad_ihl = bytes([0x41, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 9, 9, 9, 9])
        short_udp = bytes([0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 9, 9, 9, 9, 1, 2, 0, 53])

        self.assertEqual(snitchd.parse_packet(bad_ihl)["malformed"], "bad ipv4 header length")
        self.assertEqual(snitchd.parse_packet(short_udp)["malformed"], "missing udp header")

    def test_ipv4_fragments_are_malformed_not_dns_or_port_prompts(self):
        # Snitch does not reassemble fragments, so fragment bytes must not be treated as TCP/UDP ports
        snitchd = load_snitchd()
        src = socket.inet_aton("10.137.0.42")
        dst = socket.inet_aton("10.139.1.1")
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 1, 64, 17, 0, src, dst)
        fake_fragment_payload = struct.pack("!HHHH", 12345, 53, 8, 0)

        request = snitchd.parse_packet(header + fake_fragment_payload)

        self.assertEqual(request["src"], "10.137.0.42")
        self.assertEqual(request["dst"], "10.139.1.1")
        self.assertEqual(request["proto"], "udp")
        self.assertEqual(request["malformed"], "ipv4 fragments unsupported")
        self.assertIsNone(request["sport"])
        self.assertIsNone(request["dport"])

    def test_failed_rule_write_does_not_publish_in_memory_decision(self):
        # Memory must not allow traffic when the persistent YAML write failed
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            rule_file = rules_dir / "browser.yml"
            rule_file.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            setattr(snitchd, "RULES_DIR", rules_dir)
            setattr(snitchd, "RULES", {"browser": {"ip": [], "dns": []}})
            old_safe_dump = snitchd.yaml.safe_dump
            snitchd.yaml.safe_dump = lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full"))
            request = {"source": "browser", "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "host": None}

            try:
                with self.assertRaises(OSError):
                    snitchd.policy_runtime.append_rule(snitchd.context(), request, "allow")
            finally:
                snitchd.yaml.safe_dump = old_safe_dump

            self.assertEqual(snitchd.RULES, {"browser": {"ip": [], "dns": []}})

    def test_cli_decision_persistence_failure_fails_daemon(self):
        # A failed answer save/reload must not leave NFQUEUE alive with a dead CLI server thread
        snitchd = load_snitchd()
        original_handler = snitchd.queue.handle_cli_connection
        snitchd.queue.handle_cli_connection = lambda *_args: (_ for _ in ()).throw(OSError("disk full"))
        snitchd.syslog.syslog = lambda *_args: None

        try:
            with self.assertRaises(SystemExit):
                snitchd.handle_cli_connection(object())
        finally:
            snitchd.queue.handle_cli_connection = original_handler

    def test_cli_decision_systemexit_fails_daemon(self):
        # SystemExit from validation must fail the daemon, not just kill the CLI thread
        snitchd = load_snitchd()
        original_handler = snitchd.queue.handle_cli_connection
        snitchd.queue.handle_cli_connection = lambda *_args: (_ for _ in ()).throw(SystemExit("bad yaml"))
        snitchd.alerts_runtime.fatal_security_alert = lambda _ctx, key, message: (_ for _ in ()).throw(SystemExit((key, message)))

        try:
            with self.assertRaises(SystemExit) as caught:
                snitchd.handle_cli_connection(object())
        finally:
            snitchd.queue.handle_cli_connection = original_handler

        self.assertEqual(caught.exception.code[0], ("cli-decision-failed",))

    def test_cli_server_accept_failure_fails_daemon(self):
        # If the local CLI socket accept loop dies, no prompts can be answered, so fail closed
        snitchd = load_snitchd()
        class BrokenSocket:
            def accept(self):
                raise OSError("socket dead")
        snitchd.SERVER_SOCKET = BrokenSocket()
        snitchd.alerts_runtime.fatal_security_alert = lambda _ctx, key, message: (_ for _ in ()).throw(SystemExit((key, message)))

        with self.assertRaises(SystemExit) as caught:
            snitchd.cli_server()

        self.assertEqual(caught.exception.code[0], ("cli-server-failed",))

    def test_cidr_destination_service_name_and_port_range_match_existing_rules(self):
        # Manual rules may use CIDR destinations, service names like https, and port ranges
        snitchd = load_snitchd()
        setattr(snitchd, "RULES", {
            "app-signal": {
                "ip": [
                    {"ptr": "example", "dest": "93.184.216.0/24", "proto": "tcp", "port": "https", "action": "allow"},
                    {"ptr": "example", "dest": "any", "proto": "udp", "port": "1000-2000", "action": "reject"},
                ],
                "dns": [],
            }
        })

        self.assertEqual(snitchd.policy_runtime.matching_action(snitchd.context(), {"source": "app-signal", "dst": "93.184.216.34", "proto": "tcp", "dport": 443}), "allow")
        self.assertEqual(snitchd.policy_runtime.matching_action(snitchd.context(), {"source": "app-signal", "dst": "10.0.0.1", "proto": "udp", "dport": 1500}), "reject")
        self.assertIsNone(snitchd.policy_runtime.matching_action(snitchd.context(), {"source": "app-signal", "dst": "93.184.217.34", "proto": "tcp", "dport": 443}))

    def test_unknown_ipv4_protocol_is_rejected_without_prompt(self):
        # Unsupported live protocols cannot be persisted, so they must never become user prompts
        snitchd = load_snitchd()
        captured = []
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("drop"))
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "1.2.3.4", "proto": "99", "sport": None, "dport": None, "body": b"", "malformed": "unsupported ipv4 protocol"})
        setattr(snitchd.packet_handlers, "queue_prompt", lambda _ctx, request: captured.append(request))
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))
        snitchd.notify.security_notify = lambda message, *_args: events.append(("notify", message))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertEqual(captured, [])
        self.assertIn(("syslog", snitchd.syslog.LOG_WARNING, "QUBES-SNITCH SECURITY REJECT malformed 99 SRC=browser IP=10.137.0.42 DST=1.2.3.4 REASON=unsupported ipv4 protocol"), events)
        self.assertEqual(events[-1], "drop")

    def test_dns_transport_reject_logs_before_drop(self):
        # UDP/53 transport rejects are queued before nft reject rules, so Python must provide the reject log
        snitchd = load_snitchd()
        events = []
        packet = types.SimpleNamespace(get_payload=lambda: b"payload", accept=lambda: events.append("accept"), drop=lambda: events.append("drop"))
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.42": "browser"})
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "SOURCE_LABELS", {"browser": "blue"})
        setattr(snitchd, "RULES", {"browser": {"ip": [{"ptr": "resolver", "dest": "10.139.1.1", "proto": "udp", "port": "53", "action": "reject"}], "dns": []}})
        setattr(snitchd, "parse_packet", lambda _payload: {"src": "10.137.0.42", "dst": "10.139.1.1", "proto": "udp", "sport": 53000, "dport": 53, "body": b"query-a"})
        snitchd.syslog.syslog = lambda priority, message: events.append(("syslog", priority, message))

        snitchd.packet_handlers.handle_packet(snitchd.context(), packet)

        self.assertIn(("syslog", snitchd.syslog.LOG_INFO, "QUBES-SNITCH browser reject NET DST=10.139.1.1 PROTO=udp DPORT=53 REASON=rule"), events)
        self.assertEqual(events[-1], "drop")

    def test_truncated_icmp_packet_is_malformed_not_promptable(self):
        # Protocol 1 packets need an ICMP header before they can become user policy prompts
        snitchd = load_snitchd()
        src = socket.inet_aton("10.0.0.1")
        dst = socket.inet_aton("1.1.1.1")
        payload = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 1, 0, 64, 1, 0, src, dst)

        request = snitchd.packets.parse_packet(payload)

        self.assertEqual(request["proto"], "icmp")
        self.assertEqual(request["malformed"], "missing icmp header")
