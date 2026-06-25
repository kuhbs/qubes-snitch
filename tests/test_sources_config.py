# Purpose: regression tests for live dom0 source identity loading
# Scope: covers the VM-name to IP and label map used by prompts, chains, and rule filenames
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from snitch_testlib import load_snitchd


class SourcesConfigTests(unittest.TestCase):
    # Source-config tests protect the qrexec output contract between sys-snitch and dom0
    def test_config_rejects_bool_integer_fields(self):
        # YAML True is an int subclass in Python, but queue/log sizes must be real numbers
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text(
                "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: True\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n",
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                snitchd.config.read_config(path)

    def test_config_rejects_invalid_dns_cache_caps(self):
        # DNS cache caps are memory bounds, so booleans and impossible global/per-source pairs must fail
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text(
                "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 10\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n",
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                snitchd.config.read_config(path)

    def test_config_rejects_invalid_dns_cache_refresh_workers(self):
        # DNS refresh worker count bounds prompt-side resolver concurrency
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            base = "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\n"
            rest = "default_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n"
            for workers in ("True", "0", "1025"):
                path.write_text(base + f"dns_cache_refresh_workers: {workers}\n" + rest, encoding="utf-8")
                with self.assertRaises(SystemExit):
                    snitchd.config.read_config(path)

    def test_config_accepts_default_disposable_vm_name(self):
        # Generic DispVM policy uses the configured Qubes default disposable template name
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text(
                "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n",
                encoding="utf-8",
            )

            config = snitchd.config.read_config(path)

        self.assertEqual(config["default_disposable_vm_name"], "default-dvm")
        self.assertEqual(config["dns_cache_refresh_workers"], 32)
        self.assertEqual(config["prompt_protocol_colors"]["encrypted"], {("tcp", "443")})
        self.assertIn(("udp", "53"), config["prompt_protocol_colors"]["unencrypted"])

    def test_config_rejects_non_ascii_before_yaml_parse(self):
        # Config files are ASCII-only at the raw byte boundary, including comments, before PyYAML interprets them
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_bytes(b"# caf\xc3\xa9\ntheme: dark\n")

            with self.assertRaises(SystemExit) as caught:
                snitchd.config.read_config(path)

        self.assertIn("non-ASCII bytes are not allowed", str(caught.exception))

    def test_config_rejects_bad_prompt_column_widths(self):
        # Prompt widths are fixed terminal cell counts, so booleans, missing keys, and tiny columns fail
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            base = "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\n"
            colors = "prompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n"
            for widths in (
                "prompt_column_widths:\n  queue: True\n  source: 20\n  target: 32\n  service: 22\n  info: 34\n",
                "prompt_column_widths:\n  queue: 6\n  source: 4\n  target: 32\n  service: 22\n  info: 34\n",
                "prompt_column_widths:\n  queue: 6\n  source: 20\n  target: 32\n  service: 22\n",
            ):
                path.write_text(base + widths + colors, encoding="utf-8")
                with self.assertRaises(SystemExit):
                    snitchd.config.read_config(path)

    def test_config_rejects_bad_prompt_protocol_colors(self):
        # Prompt color entries are proto/port pairs only; comments carry names so runtime data stays simple
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            base = "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\n"
            for colors in (
                "prompt_protocol_colors:\n  encrypted: []\n  unencrypted:\n    - proto: icmp\n      port: 8\n",
                "prompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n      name: https\n  unencrypted: []\n",
                "prompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 443\n",
            ):
                path.write_text(base + colors, encoding="utf-8")
                with self.assertRaises(SystemExit):
                    snitchd.config.read_config(path)

    def test_generic_default_dispvm_source_must_be_numbered(self):
        # Non-numbered generic default DispVM rows are not valid policy sources; leave any live packets to unknown-source fail-hard
        snitchd = load_snitchd()
        for source in ("work", "disp12345"):
            output = f"{source}|10.138.4.5|red|DispVM|default-dvm\n"
            by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)
            self.assertEqual(by_name, {})
            self.assertEqual(by_ip, {})
            self.assertEqual(labels, {})
            self.assertEqual(display_by_ip, {})

    def test_ignored_generic_default_dispvm_rows_do_not_conflict_with_real_sources(self):
        # Ignored default-DVM provider rows can have stale IPs, so skip them before duplicate-IP checks
        snitchd = load_snitchd()
        output = "app-a|10.137.0.10|blue|AppVM|tpl-app\nwork|10.137.0.10|red|DispVM|default-dvm\n"

        by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertEqual(by_name, {"app-a": ["10.137.0.10"]})
        self.assertEqual(by_ip, {"10.137.0.10": "app-a"})
        self.assertEqual(labels, {"app-a": "blue"})
        self.assertEqual(display_by_ip, {"10.137.0.10": "app-a"})

    def test_generic_default_dispvm_accepts_one_to_four_digit_names(self):
        # Qubes generates unnamed DispVM names from dispid 0 through 9999, so every matching disp<N> length is valid
        snitchd = load_snitchd()
        for source in ("disp0", "disp7", "disp70", "disp123", "disp1234"):
            output = f"{source}|10.138.4.5|red|DispVM|default-dvm\n"
            by_name, by_ip, _labels, _display = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)
            self.assertEqual(by_name, {source: ["10.138.4.5"]})
            self.assertEqual(by_ip, {"10.138.4.5": source})

    def test_config_rejects_reserved_default_disposable_vm_name(self):
        # The configured default DVM is a Qubes template name, so sentinel collisions must fail at config load
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text(
                "theme: dark\nnotify_send: True\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: app-disp-base\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n",
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                snitchd.config.read_config(path)

    def test_dom0_source_output_maps_names_ips_and_labels(self):
        # dom0 returns one VM row with IPv4 and label; non-IPv4 is unsupported
        snitchd = load_snitchd()
        output = "app-browser|10.137.50.10|orange|AppVM|tpl-app\ndisp1234|10.138.4.5|red|DispVM|default-dvm\n"

        by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertEqual(by_name, {"app-browser": ["10.137.50.10"], "disp1234": ["10.138.4.5"]})
        self.assertEqual(by_ip, {"10.137.50.10": "app-browser", "10.138.4.5": "disp1234"})
        self.assertEqual(labels, {"app-browser": "orange", "disp1234": "red"})
        self.assertEqual(display_by_ip, {"10.137.50.10": "app-browser", "10.138.4.5": "disp1234(default-dvm)"})

    def test_dom0_source_output_rejects_non_ascii_with_clear_error(self):
        # Snitch checks trusted dom0 qrexec text here so operators see the real ASCII-policy error, not a timeout
        snitchd = load_snitchd()
        output = "app-br\u00f6wser|10.137.50.10|orange|AppVM|tpl-app\n"

        with self.assertRaises(SystemExit) as caught:
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertIn("non-ASCII source identity text is not supported", str(caught.exception))

    def test_dispvm_template_dash_sentinel_is_rejected(self):
        # qvm-ls uses - for missing data; a missing DispVM template must not become dispvm-- policy
        snitchd = load_snitchd()
        output = "disp1234|10.138.4.5|red|DispVM|-\n"

        with self.assertRaises(SystemExit):
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

    def test_dom0_source_output_ignores_sources_without_addresses(self):
        # VMs without IPv4 cannot originate forwarded packets Snitch can attribute yet
        snitchd = load_snitchd()
        output = "dom0|-|black|AdminVM|-\napp-browser|-|orange|AppVM|tpl-app\n"

        by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertEqual(by_name, {})
        self.assertEqual(by_ip, {})
        self.assertEqual(labels, {})
        self.assertEqual(display_by_ip, {})

    def test_dom0_source_output_ignores_generic_default_provider_rows(self):
        # qvm-ls includes paused VMs, but non-numbered default-DVM provider rows are not promptable policy sources
        snitchd = load_snitchd()
        output = "sys-firewall|10.137.0.6|green|DispVM|default-dvm\napp-browser|10.137.0.10|orange|AppVM|tpl-app\n"

        by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertEqual(by_name, {"app-browser": ["10.137.0.10"]})
        self.assertEqual(by_ip, {"10.137.0.10": "app-browser"})
        self.assertEqual(labels, {"app-browser": "orange"})
        self.assertEqual(display_by_ip, {"10.137.0.10": "app-browser"})

    def test_dom0_source_output_rejects_bad_source_names(self):
        # Source names become rule filenames, so path-like qrexec output must fail closed
        snitchd = load_snitchd()

        for source in ("../evil", ".", "..", "...", "-", ".hidden", "dash-"):
            with self.assertRaises(SystemExit):
                snitchd.sources_runtime.parse_sources_output(snitchd.context(), f"{source}|10.137.50.10|red|AppVM|tpl-app\n")

    def test_dom0_source_output_rejects_duplicate_source_ips(self):
        # Duplicate IPs would make a packet's source identity ambiguous, so refuse the source map
        snitchd = load_snitchd()
        output = "app-browser|10.137.50.10|orange|AppVM|tpl-app\napp-chat|10.137.50.10|purple|AppVM|tpl-app\n"

        with self.assertRaises(SystemExit):
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

    def test_rule_files_reject_bad_source_filenames(self):
        # Rule filenames become source identities and nft chain names, so reject path/syntax-like stems
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad:name.yml"
            path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")

            with self.assertRaises(SystemExit):
                snitchd.config.load_rules(Path(tmp))

    def test_rule_file_rejects_non_ascii_before_yaml_parse(self):
        # Rule files use the same raw ASCII gate as config, so comments cannot carry Unicode confusables either
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-browser.yml"
            path.write_bytes(b"# caf\xc3\xa9\nrules4: []\n\ndns: []\n")

            with self.assertRaises(SystemExit) as caught:
                snitchd.config.load_rules(Path(tmp))

        self.assertIn("non-ASCII bytes are not allowed", str(caught.exception))

    def test_dom0_source_query_has_five_second_timeout(self):
        # qrexec runs in packet-adjacent refresh paths, so a stuck dom0 service must not stall Snitch forever
        snitchd = load_snitchd()
        calls = []
        old_run = snitchd.subprocess.run
        snitchd.subprocess.run = lambda *args, **kwargs: calls.append(kwargs) or type("Result", (), {"stdout": "app-a|10.137.0.10|blue|AppVM|tpl-app\n"})()

        try:
            snitchd.sources_runtime.query_dom0_sources(snitchd.context())
        finally:
            snitchd.subprocess.run = old_run

        self.assertEqual(calls[0]["timeout"], 5)

    def test_initial_source_refresh_failure_fails_daemon_after_fail_closed_policy(self):
        # Startup qrexec failure means Qubes source identity is broken, so daemon exits after fail-closed nft is installed
        snitchd = load_snitchd()
        events = []
        with TemporaryDirectory() as tmp:
            snitchd.RULES_DIR = Path(tmp)
            config = {"notify_send": False, "pending_queue_size": 200, "dns_cache_max_per_source": 32768, "dns_cache_max_global": 131072, "dns_cache_refresh_workers": 32, "default_disposable_vm_name": "default-dvm", "limit_rate": "3/minute", "burst": 5, "log_bucket_max_entries": 4096, "prompt_protocol_colors": {"encrypted": {("tcp", "443")}, "unencrypted": {("tcp", "80"), ("udp", "53")}}}
            snitchd.config.read_config = lambda _path: config
            snitchd.RULES = {}
            snitchd.sources_runtime.query_dom0_sources = lambda _ctx: (_ for _ in ()).throw(snitchd.subprocess.TimeoutExpired("qrexec-client-vm", 5))
            snitchd.policy_runtime.load_nft = lambda _ctx: events.append("full-nft")
            snitchd.syslog.syslog = lambda *_args: events.append("log")

            snitchd.policy_runtime.load_policy_without_sources(snitchd.context())
            with self.assertRaises(SystemExit):
                snitchd.sources_runtime.refresh_sources_required(snitchd.context())

        self.assertEqual(snitchd.RULES, {})
        self.assertEqual(events, ["log"])

    def test_qubesdb_event_refreshes_sources_and_rerenders_nft(self):
        # QubesDB is the push signal; qrexec supplies the VM name/label map after the signal arrives
        snitchd = load_snitchd()
        events = []
        setattr(snitchd, "SOURCES_BY_NAME", {"app-a": ["10.137.0.10"]})
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.10": "app-a"})
        setattr(snitchd, "SOURCE_LABELS", {"app-a": "blue"})
        setattr(snitchd, "RULES", {"app-a": {"ip": [], "dns": []}})
        setattr(snitchd.sources_runtime, "query_dom0_sources", lambda _ctx: (
            {"app-a": ["10.137.0.11"], "app-b": ["10.137.0.10"]},
            {"10.137.0.11": "app-a", "10.137.0.10": "app-b"},
            {"app-a": "blue", "app-b": "green"},
            {"10.137.0.11": "app-a", "10.137.0.10": "app-b"},
        ))
        setattr(snitchd.policy_runtime, "ensure_rule_entry", lambda _ctx, source: events.append(("ensure", source)))
        setattr(snitchd.policy_runtime, "load_nft", lambda _ctx: events.append(("load_nft", dict(snitchd.SOURCES_BY_IP))))

        changed = snitchd.sources_runtime.refresh_sources_and_nft(snitchd.context(), force=True)

        self.assertTrue(changed)
        self.assertEqual(snitchd.SOURCES_BY_IP["10.137.0.10"], "app-b")
        self.assertEqual(events, [
            ("ensure", "app-a"),
            ("ensure", "app-b"),
            ("load_nft", {"10.137.0.11": "app-a", "10.137.0.10": "app-b"}),
        ])

    def test_source_refresh_queries_dom0_before_policy_lock(self):
        # qrexec can wait on dom0, so the policy lock must only protect source-map publish and nft reload
        snitchd = load_snitchd()
        events = []

        class TrackingLock:
            # Track lock ownership so the test proves qrexec runs before the shared policy state is locked
            locked = False

            def __enter__(self):
                self.locked = True

            def __exit__(self, *_args):
                self.locked = False

        lock = TrackingLock()
        setattr(snitchd, "POLICY_LOCK", lock)
        setattr(snitchd, "SOURCES_BY_NAME", {"app-a": ["10.137.0.10"]})
        setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.10": "app-a"})
        setattr(snitchd, "SOURCE_LABELS", {"app-a": "blue"})
        setattr(snitchd, "RULES", {"app-a": {"ip": [], "dns": []}})

        def query_sources(_ctx):
            # The slow qrexec step should happen before POLICY_LOCK so packet callbacks do not freeze behind dom0
            events.append(("query", lock.locked))
            return (
                {"app-a": ["10.137.0.11"]},
                {"10.137.0.11": "app-a"},
                {"app-a": "blue"},
                {"10.137.0.11": "app-a"},
            )

        setattr(snitchd.sources_runtime, "query_dom0_sources", query_sources)
        setattr(snitchd.policy_runtime, "load_nft", lambda _ctx: events.append(("load_nft", lock.locked)))

        self.assertTrue(snitchd.sources_runtime.refresh_sources_and_nft(snitchd.context(), force=True))

        self.assertEqual(events, [("query", False), ("load_nft", True)])

    def test_disappeared_dispvm_removes_pending_questions(self):
        # A queued numbered-DispVM question becomes obsolete when that disposable disappears
        snitchd = load_snitchd()
        snitchd.queue.PENDING_QUESTIONS.clear()
        snitchd.queue.PENDING_QUESTIONS[("disp1234", "net", "1.2.3.4", "tcp", 443)] = {"source": "disp1234"}
        setattr(snitchd, "SOURCES_BY_NAME", {})
        setattr(snitchd, "RULES", {"disp1234": {"ip": [], "dns": []}})

        snitchd.policy_runtime.cleanup_disposable_rule_entries(snitchd.context())

        self.assertEqual(snitchd.queue.PENDING_QUESTIONS, {})


    def test_configured_default_dispvm_policy_file_is_rejected(self):
        # Users who renamed default-dvm still must not create shared generic default disposable policy
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "dispvm-my-default.yml"
            path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")

            with self.assertRaises(SystemExit):
                snitchd.config.load_rules(Path(tmp), "my-default")

    def test_disappeared_dispvm_removes_dns_cache_hints(self):
        # Numbered DispVM names can be reused, so display-only DNS hints must disappear with the source
        snitchd = load_snitchd()
        snitchd.RULES = {"disp1234": {"ip": [], "dns": []}}
        snitchd.SOURCES_BY_NAME = {}
        snitchd.DNS_RESPONSE_CACHE = {
            ("disp1234", "1.2.3.4"): {"label": "example.com", "qname": "example.com", "qtype": "A", "expires_at": 999},
            ("browser", "1.2.3.4"): {"label": "example.org", "qname": "example.org", "qtype": "A", "expires_at": 999},
        }
        snitchd.DNS_QNAME_CACHE = {
            ("disp1234", "A", "example.com"): {"labels": {"1.2.3.4": "example.com"}, "expires_at": 999},
            ("browser", "A", "example.org"): {"labels": {"1.2.3.4": "example.org"}, "expires_at": 999},
        }

        self.assertTrue(snitchd.policy_runtime.cleanup_disposable_rule_entries(snitchd.context()))

        self.assertNotIn(("disp1234", "1.2.3.4"), snitchd.DNS_RESPONSE_CACHE)
        self.assertIn(("browser", "1.2.3.4"), snitchd.DNS_RESPONSE_CACHE)
        self.assertNotIn(("disp1234", "A", "example.com"), snitchd.DNS_QNAME_CACHE)
        self.assertIn(("browser", "A", "example.org"), snitchd.DNS_QNAME_CACHE)

    def test_stale_numbered_dispvm_answer_is_not_persisted(self):
        # Old answers for disappeared numbered DispVMs must not recreate disp1234.yml
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            snitchd.RULES_DIR = Path(tmp)
            snitchd.SOURCES_BY_NAME = {}
            request = {"source": "disp1234", "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "host": None}

            with self.assertRaises(SystemExit):
                snitchd.policy_runtime.append_rule(snitchd.context(), request, "allow")

            self.assertFalse((Path(tmp) / "disp1234.yml").exists())

    def test_disappeared_dispvm_rule_file_is_deleted_and_nft_reloaded(self):
        # Numbered DispVM identities are temporary, so stale disp1234.yml must disappear with the VM
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            events = []
            rules_dir = Path(tmp)
            disp_file = rules_dir / "disp1234.yml"
            app_file = rules_dir / "app-a.yml"
            disp_file.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            app_file.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            setattr(snitchd, "RULES_DIR", rules_dir)
            setattr(snitchd, "SOURCES_BY_NAME", {"disp1234": ["10.137.0.55"], "app-a": ["10.137.0.10"]})
            setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.55": "disp1234", "10.137.0.10": "app-a"})
            setattr(snitchd, "SOURCE_LABELS", {"disp1234": "red", "app-a": "blue"})
            setattr(snitchd, "RULES", {"disp1234": {"ip": [], "dns": []}, "app-a": {"ip": [], "dns": []}})
            setattr(snitchd.sources_runtime, "query_dom0_sources", lambda _ctx: (
                {"app-a": ["10.137.0.10"]},
                {"10.137.0.10": "app-a"},
                {"app-a": "blue"},
                {"10.137.0.10": "app-a"},
            ))
            setattr(snitchd.policy_runtime, "load_nft", lambda _ctx: events.append(("load_nft", dict(snitchd.SOURCES_BY_IP), dict(snitchd.RULES))))

            changed = snitchd.sources_runtime.refresh_sources_and_nft(snitchd.context(), force=True)

            self.assertTrue(changed)
            self.assertFalse(disp_file.exists())
            self.assertTrue(app_file.exists())
            self.assertNotIn("disp1234", snitchd.RULES)
            self.assertEqual(events, [("load_nft", {"10.137.0.10": "app-a"}, {"app-a": {"ip": [], "dns": []}})])

    def test_reused_numbered_dispvm_ip_change_cleans_old_prompts(self):
        # Qubes can reuse a numbered name before Snitch observes an absent interval, so IP change is identity change too
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            disp_file = rules_dir / "disp1234.yml"
            disp_file.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            key = ("disp1234", "net", "1.2.3.4", "tcp", 443)
            snitchd.queue.PENDING_QUESTIONS.clear()
            snitchd.queue.PENDING_QUESTIONS[key] = {"source": "disp1234"}
            setattr(snitchd, "RULES_DIR", rules_dir)
            setattr(snitchd, "SOURCES_BY_NAME", {"disp1234": ["10.137.0.55"]})
            setattr(snitchd, "SOURCES_BY_IP", {"10.137.0.55": "disp1234"})
            setattr(snitchd, "SOURCE_LABELS", {"disp1234": "red"})
            setattr(snitchd, "RULES", {"disp1234": {"ip": [], "dns": []}})
            setattr(snitchd.sources_runtime, "query_dom0_sources", lambda _ctx: (
                {"disp1234": ["10.137.0.56"]},
                {"10.137.0.56": "disp1234"},
                {"disp1234": "red"},
                {"10.137.0.56": "disp1234(default-dvm)"},
            ))
            setattr(snitchd.policy_runtime, "load_nft", lambda _ctx: None)
            snitchd.syslog.syslog = lambda *_args: None

            self.assertTrue(snitchd.sources_runtime.refresh_sources_and_nft(snitchd.context(), force=True))

            self.assertEqual(snitchd.queue.PENDING_QUESTIONS, {})
            self.assertFalse(disp_file.exists())
            self.assertEqual(snitchd.RULES["disp1234"], {"ip": [], "dns": []})

    def test_purpose_dispvm_uses_base_policy_source_and_display_name(self):
        # Purpose-specific DispVM bases share stable policy while the CLI still shows the live disposable name
        snitchd = load_snitchd()
        output = "disp6177|10.138.4.5|orange|DispVM|app-surf\n"

        by_name, by_ip, labels, display_by_ip = snitchd.sources_runtime.parse_sources_output(snitchd.context(), output)

        self.assertEqual(by_name, {"dispvm-app-surf": ["10.138.4.5"]})
        self.assertEqual(by_ip, {"10.138.4.5": "dispvm-app-surf"})
        self.assertEqual(labels, {"dispvm-app-surf": "orange"})
        self.assertEqual(display_by_ip, {"10.138.4.5": "disp6177(app-surf)"})

    def test_source_output_rejects_reserved_dispvm_prefix(self):
        # dispvm-* names are reserved for shared disposable policy files
        snitchd = load_snitchd()

        with self.assertRaises(SystemExit):
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), "dispvm-app-surf|10.137.0.10|red|AppVM|tpl-app\n")

    def test_source_output_rejects_unknown_anywhere_in_vm_name(self):
        # unknown is an internal sentinel, so Qubes VM names containing it are refused loudly
        snitchd = load_snitchd()

        with self.assertRaises(SystemExit):
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), "app-unknown-browser|10.137.0.10|red|AppVM|tpl-app\n")

    def test_source_output_rejects_disp_in_non_dispvm_name(self):
        # disp names are reserved for real Qubes DispVMs and their temporary policy files
        snitchd = load_snitchd()

        with self.assertRaises(SystemExit):
            snitchd.sources_runtime.parse_sources_output(snitchd.context(), "app-disp-browser|10.137.0.10|red|AppVM|tpl-app\n")

    def test_load_policy_deletes_numbered_dispvm_files_before_loading(self):
        # Numbered DispVM files from an old daemon lifetime must not survive startup and match a reused name
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            events = []
            rules_dir = Path(tmp)
            (rules_dir / "disp123.yml").write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            (rules_dir / "disp1234.yml").write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            (rules_dir / "app-a.yml").write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            snitchd.RULES_DIR = rules_dir
            snitchd.CONFIG_FILE = rules_dir / "config.yml"
            snitchd.config.read_config = lambda _path: {"notify_send": False, "pending_queue_size": 200, "dns_cache_max_per_source": 32768, "dns_cache_max_global": 131072, "dns_cache_refresh_workers": 32, "default_disposable_vm_name": "default-dvm", "limit_rate": "3/minute", "burst": 5, "log_bucket_max_entries": 4096, "prompt_protocol_colors": {"encrypted": {("tcp", "443")}, "unencrypted": {("tcp", "80"), ("udp", "53")}}}
            snitchd.syslog.syslog = lambda *_args: events.append(_args)

            snitchd.policy_runtime.load_policy_without_sources(snitchd.context())

            self.assertFalse((rules_dir / "disp123.yml").exists())
            self.assertFalse((rules_dir / "disp1234.yml").exists())
            self.assertIn("app-a", snitchd.RULES)
            self.assertNotIn("disp123", snitchd.RULES)
            self.assertNotIn("disp1234", snitchd.RULES)
            self.assertTrue(events)

    def test_numbered_dispvm_cleanup_uses_one_to_four_digit_contract(self):
        # Cleanup must not drift from the Qubes disp0..disp9999 naming contract
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            for name in ("disp0", "disp12", "disp123", "disp1234", "disp12345"):
                (rules_dir / f"{name}.yml").write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            snitchd.RULES_DIR = rules_dir
            snitchd.RULES = {name: {"ip": [], "dns": []} for name in ("disp0", "disp12", "disp123", "disp1234", "disp12345")}
            snitchd.syslog.syslog = lambda *_args: None

            self.assertTrue(snitchd.policy_runtime.cleanup_numbered_dispvm_files(snitchd.context()))

            self.assertFalse((rules_dir / "disp0.yml").exists())
            self.assertFalse((rules_dir / "disp12.yml").exists())
            self.assertFalse((rules_dir / "disp123.yml").exists())
            self.assertFalse((rules_dir / "disp1234.yml").exists())
            self.assertTrue((rules_dir / "disp12345.yml").exists())
            self.assertNotIn("disp0", snitchd.RULES)
            self.assertNotIn("disp12", snitchd.RULES)
            self.assertNotIn("disp123", snitchd.RULES)
            self.assertNotIn("disp1234", snitchd.RULES)
            self.assertIn("disp12345", snitchd.RULES)

    def test_known_source_creates_memory_bucket_not_empty_yaml(self):
        # Merely seeing a source should not create empty YAML, especially for prewarmed DispVMs
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            snitchd.RULES_DIR = Path(tmp)
            snitchd.RULES = {}

            changed = snitchd.policy_runtime.ensure_rule_entry(snitchd.context(), "disp3094")

            self.assertTrue(changed)
            self.assertEqual(snitchd.RULES["disp3094"], {"ip": [], "dns": []})
            self.assertFalse((Path(tmp) / "disp3094.yml").exists())

    def test_dispvm_default_policy_file_is_rejected(self):
        # default-dvm is not a purpose-specific disposable base, so shared policy for it is unsafe
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "dispvm-default-dvm.yml"
            path.write_text("rules4: []\n\ndns: []\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                snitchd.config.load_rules(Path(tmp))

    def test_qubesdb_watcher_failure_exits_daemon(self):
        # Source identity updates are security-critical; a dead watcher must fail the daemon
        snitchd = load_snitchd()
        events = []
        class BrokenQdb:
            def watch(self, path):
                pass
            def read_watch(self):
                raise RuntimeError("boom")
        snitchd.qubesdb.QubesDB = lambda: BrokenQdb()
        snitchd.alerts_runtime.fatal_security_alert = lambda _ctx, key, message: (_ for _ in ()).throw(SystemExit((key, message)))

        with self.assertRaises(SystemExit) as caught:
            snitchd.sources_runtime.qubesdb_source_watcher(snitchd.context())
        self.assertEqual(caught.exception.code[0], ("qubesdb-watcher-failed",))

    def test_open_socket_fails_when_socket_path_already_exists(self):
        # Existing socket state is left to bind(); daemon startup should not probe local sockets
        snitchd = load_snitchd()
        with TemporaryDirectory() as tmp:
            snitchd.SOCKET_FILE = Path(tmp) / "socket"
            snitchd.SOCKET_FILE.write_text("stale", encoding="utf-8")
            with self.assertRaises(SystemExit) as caught:
                snitchd.open_socket()
        self.assertIn("cannot bind qubes-snitchd socket", str(caught.exception))

    def test_qubesdb_watch_paths_match_qubes_firewall_signals(self):
        # sys-firewall watches the same QubesDB paths, but Snitch refreshes richer qrexec metadata after the event
        snitchd = load_snitchd()

        self.assertTrue(snitchd.sources_runtime.qubesdb_source_event("/connected-ips"))
        self.assertFalse(snitchd.sources_runtime.qubesdb_source_event("/connected-ips6"))
        self.assertTrue(snitchd.sources_runtime.qubesdb_source_event("/qubes-firewall/10.137.0.10"))
        self.assertFalse(snitchd.sources_runtime.qubesdb_source_event("/name"))

    def test_dispvm_template_names_get_reserved_vm_name_checks(self):
        # Purpose-specific DispVM bases become policy filenames, so reserved template names must fail too
        snitchd = load_snitchd()
        for template in ("app-unknown-base", "app-disp-base"):
            with self.assertRaises(SystemExit):
                snitchd.sources_runtime.parse_sources_output(snitchd.context(), f"disp1234|10.138.4.5|red|DispVM|{template}\n")

    def test_default_dvm_template_never_becomes_purpose_specific_policy_source(self):
        # default-dvm is Qubes' generic default disposable base even when the configured default has a custom name
        snitchd = load_snitchd()
        output = "disp1234|10.138.4.5|red|DispVM|default-dvm\n"

        by_name, by_ip, _labels, _display = snitchd.config.parse_sources_output(output, default_dvm_template="my-default")

        self.assertEqual(by_name, {"disp1234": ["10.138.4.5"]})
        self.assertEqual(by_ip, {"10.138.4.5": "disp1234"})

    def test_configured_default_dvm_name_gets_reserved_vm_name_checks(self):
        # The generic default DispVM template is still a real Qubes template name, so sentinel collisions must fail
        snitchd = load_snitchd()
        output = "disp1234|10.138.4.5|red|DispVM|evilunknown-dvm\n"

        with self.assertRaises(SystemExit):
            snitchd.config.parse_sources_output(output, default_dvm_template="evilunknown-dvm")
