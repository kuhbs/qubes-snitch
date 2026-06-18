# Purpose: regression tests for user-facing Qubes Snitch CLI behavior
# Scope: checks prompt rendering, missing-daemon errors, and duplicate-CLI locking without a real daemon
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from snitch_testlib import load_cli


PROMPT_CONFIG = {
    "theme": "dark",
    "prompt_column_widths": {
        "queue": 10,
        "source": 18,
        "target": 25,
        "dns": 42,
        "service": 22,
    },
    "prompt_protocol_colors": {
        "encrypted": {("tcp", "443"), ("tcp", "993")},
        "unencrypted": {("tcp", "80"), ("udp", "53")},
    },
}


class CliPromptTests(unittest.TestCase):
    # CLI tests stay here so socket, terminal, and prompt behavior do not get mixed with packet tests
    def test_cli_header_is_bold_without_color_change(self):
        # The header is bold for scanning, but it must not pick a warning/source color
        cli = load_cli()

        header = cli.header_line(PROMPT_CONFIG)

        self.assertTrue(header.startswith("\033[1mQ"))
        self.assertIn("SOURCE", header)
        self.assertIn("TARGET", header)
        self.assertIn("DNS", header)
        self.assertIn("SERVICE", header)
        self.assertIn("ACTION", header)
        self.assertNotIn("INFO", header)
        self.assertTrue(header.endswith("\033[0m\n"))
        self.assertNotIn("\033[9", header)
        self.assertNotIn("\033[3", header)

    def test_cli_renders_known_source_prompt(self):
        # Prompts come from dom0-mapped sources and include the Qubes label color when known
        cli = load_cli()
        request = {"source": "browser", "source_label": "blue", "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "host": None}

        line = cli.packet_line(request, PROMPT_CONFIG)

        self.assertIn("\033[94mbrowser", line)
        self.assertIn("\033[39m1.2.3.4\033[0m", line)
        self.assertIn("\033[91mno PTR\033[0m", line)
        self.assertIn("\033[92mhttps 443/tcp\033[0m", line)

    def test_cli_colors_dns_transport_by_resolver(self):
        # DNS resolver transport overrides generic udp/53 coloring so direct external DNS is visibly risky
        cli = load_cli()
        internal = {"source": "browser", "source_label": "blue", "dst": "10.139.1.1", "proto": "udp", "dport": 53, "host": None}
        external = {"source": "browser", "source_label": "blue", "dst": "8.8.8.8", "proto": "udp", "dport": 53, "host": "PTR dns.google"}

        internal_line = cli.packet_line(internal, PROMPT_CONFIG)
        external_line = cli.packet_line(external, PROMPT_CONFIG)

        self.assertIn("\033[96m10.139.1.1\033[0m", internal_line)
        self.assertIn("\033[96mqubes.dns-1.internal\033[0m", internal_line)
        self.assertIn("\033[96mdomain 53/udp\033[0m", internal_line)
        self.assertIn("\033[91m8.8.8.8\033[0m", external_line)
        self.assertIn("\033[91mdns.google\033[0m", external_line)
        self.assertIn("\033[91mdomain 53/udp\033[0m", external_line)

    def test_cli_colors_dns_questions_by_resolver(self):
        # DNS qname prompts show resolver IP in TARGET, qname in DNS, and qtype in SERVICE
        cli = load_cli()
        internal = {"kind": "dns", "source": "browser", "source_label": "blue", "dst": "10.139.1.2", "qname": "updates.signal.org", "qtype": "A"}
        external = {"kind": "dns", "source": "browser", "source_label": "blue", "dst": "8.8.8.8", "qname": "example.org", "qtype": "A"}

        internal_line = cli.packet_line(internal, PROMPT_CONFIG)
        external_line = cli.packet_line(external, PROMPT_CONFIG)

        self.assertIn("\033[96m10.139.1.2\033[0m", internal_line)
        self.assertIn("\033[96mupdates.signal.org\033[0m", internal_line)
        self.assertIn("\033[96mDNS A\033[0m", internal_line)
        self.assertIn("\033[91m8.8.8.8\033[0m", external_line)
        self.assertIn("\033[91mexample.org\033[0m", external_line)
        self.assertIn("\033[91mDNS A\033[0m", external_line)

    def test_cli_colors_normal_ip_dns_and_service_cells(self):
        # For normal IP traffic, TARGET stays plain while DNS quality and SERVICE get their own colors
        cli = load_cli()
        dns_cached = {"source": "browser", "source_label": "blue", "dst": "104.18.2.166", "proto": "tcp", "dport": 443, "host": "DNS updates.signal.org"}
        ptr_only = {"source": "browser", "source_label": "blue", "dst": "203.0.113.10", "proto": "tcp", "dport": 993, "host": "PTR mail.example.com"}
        no_ptr = {"source": "browser", "source_label": "blue", "dst": "193.174.160.18", "proto": "tcp", "dport": 9999, "host": None}
        icmp = {"source": "browser", "source_label": "blue", "dst": "162.55.47.18", "proto": "icmp", "dport": None, "host": "DNS blunix.com"}
        qubes_dns_1 = {"source": "browser", "source_label": "blue", "dst": "10.139.1.1", "proto": "icmp", "dport": None, "host": None}
        qubes_dns_2 = {"source": "browser", "source_label": "blue", "dst": "10.139.1.2", "proto": "icmp", "dport": None, "host": None}

        dns_line = cli.packet_line(dns_cached, PROMPT_CONFIG)
        ptr_line = cli.packet_line(ptr_only, PROMPT_CONFIG)
        no_ptr_line = cli.packet_line(no_ptr, PROMPT_CONFIG)
        icmp_line = cli.packet_line(icmp, PROMPT_CONFIG)
        qubes_dns_1_line = cli.packet_line(qubes_dns_1, PROMPT_CONFIG)
        qubes_dns_2_line = cli.packet_line(qubes_dns_2, PROMPT_CONFIG)

        self.assertIn("\033[39m104.18.2.166\033[0m", dns_line)
        self.assertIn("\033[92mupdates.signal.org\033[0m", dns_line)
        self.assertIn("\033[92mhttps 443/tcp\033[0m", dns_line)
        self.assertIn("\033[93mPTR mail.example.com\033[0m", ptr_line)
        self.assertIn("\033[92mimaps 993/tcp\033[0m", ptr_line)
        self.assertIn("\033[91mno PTR\033[0m", no_ptr_line)
        self.assertIn("\033[91m9999/tcp\033[0m", no_ptr_line)
        self.assertIn("\033[91micmp\033[0m", icmp_line)
        self.assertIn("\033[92mblunix.com\033[0m", icmp_line)
        self.assertIn("\033[96mqubes.dns-1.internal\033[0m", qubes_dns_1_line)
        self.assertIn("\033[96mqubes.dns-2.internal\033[0m", qubes_dns_2_line)

    def test_cli_keeps_action_aligned_after_long_dns_column(self):
        # Long DNS cells may overflow, but SERVICE padding shrinks so ACTION stays aligned
        cli = load_cli()
        long_request = {"source": "browser", "source_label": "blue", "dst": "34.107.221.82", "proto": "tcp", "dport": 80, "host": "DNS very-long-updates-subdomain.signal.org"}
        normal_request = {"source": "browser", "source_label": "blue", "dst": "151.101.2.132", "proto": "tcp", "dport": 80, "host": "DNS deb.debian.org"}

        long_line = cli.packet_line(long_request, PROMPT_CONFIG)
        normal_line = cli.packet_line(normal_request, PROMPT_CONFIG)

        self.assertEqual(long_line.index("[a/R]"), normal_line.index("[a/R]"))

    def test_cli_sanitizes_control_characters_from_display_fields(self):
        # PTR/DNS display text is remote-controlled, so it must not create fake terminal rows
        cli = load_cli()
        request = {"source": "browser\nFAKE", "source_label": "blue", "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "host": "PTR good.example\nFAKE\x1b[31m"}

        line = cli.packet_line(request, PROMPT_CONFIG)

        self.assertNotIn("\nFAKE", line)
        self.assertNotIn("\x1b[31m", line)
        self.assertIn("PTR good.example FAKE [31m", line)

    def test_cli_reports_daemon_not_running(self):
        # A user launching the CLI before the daemon starts needs an immediate readable error
        cli = load_cli()
        with TemporaryDirectory() as td:
            cli.SOCKET_FILE = Path(td) / "socket"

            with self.assertRaisesRegex(SystemExit, "qubes-snitchd is not running"):
                cli.connect_socket()

    def test_cli_rejects_second_prompt_reader(self):
        # Only one terminal should consume queued questions, otherwise two users/processes could answer different prompts
        cli = load_cli()
        with TemporaryDirectory() as td:
            cli.LOCK_FILE = Path(td) / "cli.lock"
            first_lock = cli.acquire_cli_lock()

            with self.assertRaisesRegex(SystemExit, "another qubes-snitch is already running"):
                cli.acquire_cli_lock()

            first_lock.close()
