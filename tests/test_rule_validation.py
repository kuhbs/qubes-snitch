# Purpose: regression tests for persisted rule-file validation
# Scope: rejects YAML shapes that would make nft rendering unsafe or ambiguous
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from snitch_testlib import load_snitchd


class RuleValidationTests(unittest.TestCase):
    # Rule-validation tests protect the hand-editable YAML contract
    def test_rule_file_rejects_destination_lists(self):
        # One rule must describe one destination; lists would hide several firewall decisions in one YAML entry
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example.com", "dest": ["93.184.216.34"], "proto": "tcp", "port": 443, "action": "allow"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_non_ipv4_in_rules4(self):
        # Snitch supports IPv4 flow rules only, so non-IPv4 destinations must fail validation
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example.com", "dest": "2606:2800:220:1:248:1893:25c8:1946", "proto": "tcp", "port": 443, "action": "allow"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_accepts_cidr_destination_service_name_and_port_range(self):
        # CIDR destinations, service names, and port ranges are valid supported manual YAML forms
        snitchd = load_snitchd()
        data = {
            "rules4": [
                {"ptr": "example", "dest": "93.184.216.0/24", "proto": "tcp", "port": "https", "action": "allow"},
                {"ptr": "example", "dest": "any", "proto": "udp", "port": "1000-2000", "action": "reject"},
            ],
            "dns": [],
        }

        snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_all_ipv4_cidr_destination(self):
        # Broad destination policy must use Snitch's explicit any spelling, not an all-IPv4 CIDR
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "any", "dest": "0.0.0.0/0", "proto": "tcp", "port": "443", "action": "allow"}],
            "dns": [],
        }

        with self.assertRaisesRegex(SystemExit, "use dest: any"):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_append_flow_rule_rejects_tcp_udp_port_zero(self):
        # Port 0 is not a real TCP/UDP destination port and must not persist as port:any
        snitchd = load_snitchd()
        data = {"rules4": [], "dns": []}

        with self.assertRaises(SystemExit):
            snitchd.policy.append_flow_rule(
                {"kind": "net", "source": "browser", "dst": "1.2.3.4", "proto": "tcp", "dport": 0, "host": None},
                "allow",
                data,
                {},
            )

    def test_rule_file_rejects_bad_protocol(self):
        # Protocol names are inserted into nft expressions, so validation must reject syntax-like text
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example", "dest": "any", "proto": "tcp; accept", "port": "any", "action": "allow"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_unknown_service_name(self):
        # Service-name ports must resolve locally before they are written into nft rules
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example", "dest": "any", "proto": "tcp", "port": "definitely-not-a-service", "action": "allow"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_bool_port(self):
        # YAML True is an int subclass in Python, but it is not a meaningful nft port
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example", "dest": "any", "proto": "tcp", "port": True, "action": "allow"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file("rules.yml", data)

    def test_rule_file_rejects_unknown_flow_actions(self):
        # Flow rules only support allow/reject; unknown words should not reach nft rendering
        snitchd = load_snitchd()
        data = {
            "rules4": [{"ptr": "example", "dest": "any", "proto": "tcp", "port": 443, "action": "deny"}],
            "dns": [],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)


    def test_rule_file_rejects_single_label_and_punycode_dns_qnames(self):
        # Manual DNS YAML must match live DNS policy: normal dotted ASCII names only, no IDN/punycode
        snitchd = load_snitchd()
        for qname in ("localhost", "xn--pple-43d.example"):
            data = {"rules4": [], "dns": [{"qname": qname, "qtype": "A", "action": "allow"}]}

            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("rules.yml"), data)

    def test_rule_file_rejects_generic_dns_type_aliases(self):
        # YAML qtypes must be exact supported names, not dnspython TYPE#### aliases or numeric text
        snitchd = load_snitchd()
        for qtype in ("TYPE1", "type65", "1"):
            data = {"rules4": [], "dns": [{"qname": "example.com", "qtype": qtype, "action": "allow"}]}

            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("rules.yml"), data)

    def test_rule_file_rejects_all_numeric_protocol_strings(self):
        # Numeric protocols are not part of the rule schema; require icmp, tcp, or udp
        snitchd = load_snitchd()
        for proto in ("01", "06", "17", "99"):
            data = {"rules4": [{"ptr": "x", "dest": "1.2.3.4", "proto": proto, "port": "any", "action": "allow"}], "dns": []}

            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("rules.yml"), data)

    def test_rule_file_rejects_unquoted_numeric_port_scalars(self):
        # PyYAML integer ports lose original spelling, so users must quote ports as strings
        snitchd = load_snitchd()
        data = {"rules4": [{"ptr": "x", "dest": "1.2.3.4", "proto": "tcp", "port": 443, "action": "allow"}], "dns": []}

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("rules.yml"), data)

    def test_rule_file_rejects_unknown_dns_actions(self):
        # DNS rules use the same allow/reject action vocabulary as normal flow rules
        snitchd = load_snitchd()
        data = {
            "rules4": [],
            "dns": [{"qname": "example.com", "qtype": "A", "action": "deny"}],
        }

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_numeric_tcp_udp_aliases(self):
        # 6 and 17 are TCP/UDP protocol numbers; manual YAML must use tcp/udp so DNS ordering stays correct
        snitchd = load_snitchd()
        for proto in ("6", "17"):
            data = {"rules4": [{"ptr": "example", "dest": "any", "proto": proto, "port": "any", "action": "allow"}], "dns": []}
            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_rule_file_rejects_bad_dns_qname_and_qtype(self):
        # Bad manual DNS policy must abort instead of silently creating a dead rule
        snitchd = load_snitchd()
        for rule in (
            {"qname": "bad..example", "qtype": "A", "action": "allow"},
            {"qname": "example.com", "qtype": "bad type", "action": "allow"},
            {"qname": "example.com", "qtype": "NOTAREALTYPE", "action": "allow"},
            {"qname": "example.com", "qtype": "99999", "action": "allow"},
            {"qname": "example.com", "qtype": "TYPE65536", "action": "allow"},
        ):
            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("app-signal.yml"), {"rules4": [], "dns": [rule]})

    def test_rule_file_accepts_srv_style_dns_qname(self):
        # Live DNS can ask SRV-style names, so validation must accept the same qnames the daemon can persist
        snitchd = load_snitchd()
        data = {"rules4": [], "dns": [{"qname": "_http._tcp.deb.debian.org", "qtype": "SRV", "action": "allow"}]}

        snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

        self.assertEqual(data["dns"][0]["qname"], "_http._tcp.deb.debian.org")

    def test_rule_file_rejects_srv_qname_with_single_label_suffix(self):
        # Manual SRV rules use _service._proto plus a normal dotted suffix, not local single-label names
        snitchd = load_snitchd()
        data = {"rules4": [], "dns": [{"qname": "_http._tcp.localhost", "qtype": "SRV", "action": "allow"}]}

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("app-signal.yml"), data)

    def test_reserved_unknown_rule_file_is_rejected(self):
        # unknown is a runtime sentinel, not a real source policy file
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "unknown.yml"
            path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                snitchd.config.load_rules(Path(tmp))

    def test_path_like_source_rule_filenames_are_rejected(self):
        # Source filenames must start and end with normal name characters, not path-like dots or dashes
        snitchd = load_snitchd()
        for filename in ("..yml", ".hidden.yml", "-dash.yml", "dash-.yml"):
            with TemporaryDirectory() as tmp:
                path = Path(tmp) / filename
                path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
                with self.assertRaises(SystemExit):
                    snitchd.config.load_rules(Path(tmp))

    def test_nft_renders_cidr_service_name_and_port_range(self):
        # Rendering should include the invalid guard, scoped reply accept, and CIDR/service/range rules
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"app-signal": ["10.137.50.20"]}, {"app-signal": {"ip": [
            {"ptr": "example", "dest": "93.184.216.0/24", "proto": "tcp", "port": "https", "action": "allow"},
            {"ptr": "example", "dest": "any", "proto": "udp", "port": "1000-2000", "action": "reject"},
        ], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        self.assertTrue(nft.startswith("destroy table inet qubes_snitch\n"))
        self.assertIn("ct state invalid limit rate 3/minute burst 5 packets log prefix \"QUBES-SNITCH invalid \" counter reject with icmpx admin-prohibited", nft)
        self.assertIn("ip daddr 10.137.50.20 ct state established,related ct direction reply accept", nft)
        self.assertIn("meta nfproto ipv4 ip daddr 93.184.216.0/24 tcp dport 443 accept", nft)
        self.assertIn("meta nfproto ipv4 udp dport 1000-2000 limit rate 3/minute burst 5 packets log", nft)

    def test_nft_unknown_chain_does_not_render_persisted_rules(self):
        # unknown is a sentinel chain only; persisted unknown.yml rules are refused before rendering
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"app-signal": ["10.137.50.20"]}, {"app-signal": {"ip": [], "dns": []}, "unknown": {"ip": [
            {"ptr": "bad", "dest": "any", "proto": "tcp", "port": 443, "action": "allow"},
        ], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        self.assertNotIn("tcp dport 443 accept", nft)
        self.assertIn("QUBES-SNITCH unknown reject", nft)

    def test_nft_chain_names_do_not_collide_for_similar_source_names(self):
        # Qubes VM names can contain different separators, so nft chain names must stay unique after sanitizing
        snitchd = load_snitchd()
        chain_a = snitchd.nft.nft_chain_name("app-a")
        chain_b = snitchd.nft.nft_chain_name("app_a")

        self.assertNotEqual(chain_a, chain_b)

    def test_policy_matching_preserves_yaml_order_for_duplicate_exact_rules(self):
        # First matching YAML list entry wins; later duplicate exact rules cannot override through an index
        snitchd = load_snitchd()
        request = {"source": "browser", "dst": "1.2.3.4", "proto": "tcp", "dport": 443}
        rules = {"browser": {"ip": [
            {"ptr": "first", "dest": "1.2.3.4", "proto": "tcp", "port": 443, "action": "reject"},
            {"ptr": "second", "dest": "1.2.3.4", "proto": "tcp", "port": 443, "action": "allow"},
        ], "dns": []}}

        self.assertEqual(snitchd.policy.matching_action(request, rules), "reject")

    def test_rule_file_rejects_duplicate_yaml_keys(self):
        # Duplicate YAML keys are fatal because PyYAML's default overwrite would hide policy
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "browser.yml"
            path.write_text("rules4: []\nrules4: []\ndns: []\n", encoding="utf-8")

            with self.assertRaises(SystemExit):
                snitchd.config.read_yaml(path)

    def test_rule_file_rejects_port_on_non_tcp_udp(self):
        # ICMP/numeric protocols are protocol-only in Snitch's schema
        snitchd = load_snitchd()
        data = {"rules4": [{"ptr": "ping", "dest": "any", "proto": "icmp", "port": 8, "action": "allow"}], "dns": []}

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("browser.yml"), data)

    def test_rule_file_rejects_numeric_icmp_alias(self):
        # 1 is ICMP by number; manual YAML must use icmp by name so Python and nft policy agree
        snitchd = load_snitchd()
        data = {"rules4": [{"ptr": "ping", "dest": "any", "proto": "1", "port": "any", "action": "allow"}], "dns": []}

        with self.assertRaises(SystemExit):
            snitchd.config.validate_rule_file(Path("browser.yml"), data)

    def test_rule_file_rejects_non_mapping_rule_entries(self):
        # Rule-list entries must be mappings so bad YAML fails validation cleanly
        snitchd = load_snitchd()
        for data in ({"rules4": [1], "dns": []}, {"rules4": [], "dns": [None]}):
            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("browser.yml"), data)

    def test_rule_file_rejects_non_string_dns_qname(self):
        # YAML scalars like null/true/123 must not silently become unrelated qname strings
        snitchd = load_snitchd()
        for qname in (None, True, 123):
            data = {"rules4": [], "dns": [{"qname": qname, "qtype": "A", "action": "allow"}]}
            with self.assertRaises(SystemExit):
                snitchd.config.validate_rule_file(Path("browser.yml"), data)

    def test_hyphenated_service_name_is_not_treated_as_port_range(self):
        # /etc/services names may contain hyphens; ranges only parse when both sides are digits
        snitchd = load_snitchd()

        self.assertEqual(snitchd.packets.normalize_port("domain-s", "tcp"), "853")

    def test_nft_evaluates_yaml_rules_before_established_accept(self):
        # Saved rejects must beat established/related so YAML order remains first-match truth after policy changes
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [{"ptr": "web", "dest": "1.2.3.4", "proto": "tcp", "port": "443", "action": "reject"}], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]
        chain = nft[nft.index("chain source_browser"):nft.index("chain source_unknown")]

        self.assertLess(forward.index("ip saddr 10.137.0.42 jump"), forward.index("ct state established,related ct direction reply accept"))
        self.assertLess(chain.index("tcp dport 443"), chain.rindex("queue num"))
        self.assertNotIn("ct state established,related ct direction reply accept", chain)

    def test_established_reply_rejects_beat_known_destination_accept(self):
        # Already-established remote replies must stop when a saved reject is added for that flow
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [{"ptr": "web", "dest": "1.2.3.4", "proto": "tcp", "port": "443", "action": "reject"}], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]

        reverse_reject = "ip saddr 1.2.3.4 ip daddr 10.137.0.42 tcp sport 443 ct state established,related"
        established_accept = "ip daddr 10.137.0.42 ct state established,related ct direction reply accept"
        self.assertIn(reverse_reject, forward)
        self.assertLess(forward.index(reverse_reject), forward.index(established_accept))

    def test_established_reply_rules_preserve_yaml_first_match_order(self):
        # A later broad reject must not break replies for an earlier specific allow
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [
            {"ptr": "allow-web", "dest": "1.2.3.4", "proto": "tcp", "port": "443", "action": "allow"},
            {"ptr": "reject-rest", "dest": "any", "proto": "tcp", "port": "any", "action": "reject"},
        ], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]

        reverse_allow = "ip saddr 1.2.3.4 ip daddr 10.137.0.42 tcp sport 443 ct state established,related ct direction reply"
        broad_reject = "ip daddr 10.137.0.42 meta l4proto tcp ct state established,related"
        self.assertIn(reverse_allow, forward)
        self.assertIn(broad_reject, forward)
        self.assertLess(forward.index(reverse_allow), forward.index(broad_reject))

    def test_inter_vm_established_reply_accepts_before_reply_source_jump(self):
        # Replies from a known VM must not become a new prompt from that VM when another source allowed the flow
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft(
            {"client": ["10.137.0.42"], "server": ["10.137.0.43"]},
            {
                "client": {"ip": [{"ptr": "server", "dest": "10.137.0.43", "proto": "tcp", "port": "443", "action": "allow"}], "dns": []},
                "server": {"ip": [], "dns": []},
                "unknown": {"ip": [], "dns": []},
            },
            snitchd.CONFIG,
            snitchd.NFT_TABLE,
            snitchd.QUEUE_NUM,
        )
        forward = nft[nft.index("chain forward"):nft.index("chain source_client")]

        reverse_allow = "ip saddr 10.137.0.43 ip daddr 10.137.0.42 tcp sport 443 ct state established,related ct direction reply"
        server_jump = "ip saddr 10.137.0.43 jump source_server"
        self.assertIn(reverse_allow, forward)
        self.assertLess(forward.index(reverse_allow), forward.index(server_jump))

    def test_inter_vm_broad_reply_rules_beat_peer_source_jump(self):
        # A peer VM's broad allow must not bypass this VM's broad established-reply reject
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft(
            {"client": ["10.137.0.42"], "server": ["10.137.0.43"]},
            {
                "client": {"ip": [{"ptr": "reject-rest", "dest": "any", "proto": "tcp", "port": "any", "action": "reject"}], "dns": []},
                "server": {"ip": [{"ptr": "allow-rest", "dest": "any", "proto": "tcp", "port": "any", "action": "allow"}], "dns": []},
                "unknown": {"ip": [], "dns": []},
            },
            snitchd.CONFIG,
            snitchd.NFT_TABLE,
            snitchd.QUEUE_NUM,
        )
        forward = nft[nft.index("chain forward"):nft.index("chain source_client")]

        client_reply_reject = "ip daddr 10.137.0.42 meta l4proto tcp ct state established,related ct direction reply"
        server_jump = "ip saddr 10.137.0.43 jump source_server"
        self.assertIn(client_reply_reject, forward)
        self.assertLess(forward.index(client_reply_reject), forward.index(server_jump))

    def test_inter_vm_udp_reply_to_port_53_beats_dns_source_jump(self):
        # Established replies to a client source port 53 must not be misread as the server VM's DNS query
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft(
            {"client": ["10.137.0.42"], "server": ["10.137.0.43"]},
            {
                "client": {"ip": [{"ptr": "server", "dest": "10.137.0.43", "proto": "udp", "port": "9999", "action": "allow"}], "dns": []},
                "server": {"ip": [], "dns": []},
                "unknown": {"ip": [], "dns": []},
            },
            snitchd.CONFIG,
            snitchd.NFT_TABLE,
            snitchd.QUEUE_NUM,
        )
        forward = nft[nft.index("chain forward"):nft.index("chain source_client")]

        reply_accept = "ip saddr 10.137.0.43 ip daddr 10.137.0.42 udp sport 9999 ct state established,related"
        server_dns_jump = "ip saddr 10.137.0.43 udp dport 53 jump source_server"
        self.assertIn(reply_accept, forward)
        self.assertLess(forward.index(reply_accept), forward.index(server_dns_jump))

    def test_broad_reply_accepts_do_not_bypass_real_source_policy(self):
        # Broad reply accepts must match conntrack reply direction so client-originated packets still hit client policy
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft(
            {"client": ["10.137.0.42"], "server": ["10.137.0.43"]},
            {
                "client": {"ip": [{"ptr": "server", "dest": "10.137.0.43", "proto": "tcp", "port": "any", "action": "reject"}], "dns": []},
                "server": {"ip": [{"ptr": "rest", "dest": "any", "proto": "tcp", "port": "any", "action": "allow"}], "dns": []},
                "unknown": {"ip": [], "dns": []},
            },
            snitchd.CONFIG,
            snitchd.NFT_TABLE,
            snitchd.QUEUE_NUM,
        )
        forward = nft[nft.index("chain forward"):nft.index("chain source_client")]

        server_broad_reply_accept = "ip daddr 10.137.0.43 meta l4proto tcp ct state established,related ct direction reply accept"
        client_jump = "ip saddr 10.137.0.42 jump source_client"
        self.assertLess(forward.index(server_broad_reply_accept), forward.index(client_jump))
        self.assertIn("ct direction reply", forward)

    def test_broad_external_reply_rules_preserve_yaml_first_match_order(self):
        # A broad external allow before a specific reject must still win for established replies
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [
            {"ptr": "allow-web", "dest": "any", "proto": "tcp", "port": "443", "action": "allow"},
            {"ptr": "reject-one", "dest": "1.2.3.4", "proto": "tcp", "port": "443", "action": "reject"},
        ], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]

        broad_allow = "ip daddr 10.137.0.42 tcp sport 443 ct state established,related ct direction reply accept"
        specific_reject = "ip saddr 1.2.3.4 ip daddr 10.137.0.42 tcp sport 443 ct state established,related ct direction reply"
        self.assertIn(broad_allow, forward)
        self.assertIn(specific_reject, forward)
        self.assertLess(forward.index(broad_allow), forward.index(specific_reject))

    def test_full_nft_queues_unknown_sources_before_invalid_conntrack_reject(self):
        # Unknown source identity is daemon-fatal, so full nft must not kernel-reject invalid packets before source lookup
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)

        self.assertLess(nft.index("jump source_unknown"), nft.index("ct state invalid"))

    def test_known_source_chain_rejects_invalid_conntrack_before_allows(self):
        # Moving invalid handling after source jumps must not let known-source saved allows accept invalid packets
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [{"ptr": "web", "dest": "any", "proto": "tcp", "port": "any", "action": "allow"}], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        chain = nft[nft.index("chain source_browser"):nft.index("chain source_unknown")]

        self.assertLess(chain.index("ct state invalid"), chain.index("meta nfproto ipv4 meta l4proto tcp accept"))
        self.assertLess(chain.index("ct state invalid"), chain.index("queue num"))

    def test_global_established_accept_handles_reply_traffic_before_unknown_source(self):
        # Reply packets use the remote host as source, so established/related must be accepted before unknown-source dispatch
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]

        self.assertLess(forward.index("ip daddr 10.137.0.42 ct state established,related ct direction reply accept"), forward.index("jump source_unknown"))
        self.assertLess(forward.index("ip saddr 10.137.0.42 jump"), forward.index("ct state established,related ct direction reply accept"))

    def test_established_accept_is_scoped_to_known_reply_destinations(self):
        # Unknown source IPs are daemon-fatal, so fallback established accepts must match only conntrack replies
        snitchd = load_snitchd()
        nft = snitchd.nft.render_nft({"browser": ["10.137.0.42"]}, {"browser": {"ip": [], "dns": []}, "unknown": {"ip": [], "dns": []}}, snitchd.CONFIG, snitchd.NFT_TABLE, snitchd.QUEUE_NUM)
        forward = nft[nft.index("chain forward"):nft.index("chain source_browser")]

        self.assertNotIn("  meta nfproto ipv4 ct state established,related ct direction reply accept", forward)
        self.assertIn("  ip daddr 10.137.0.42 ct state established,related ct direction reply accept", forward)
