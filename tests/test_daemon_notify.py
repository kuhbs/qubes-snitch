# Purpose: regression tests for daemon-side desktop notifications
# Scope: proves notify-send arguments and failure propagation
import unittest
from pathlib import Path

from snitch_testlib import load_snitchd


class DaemonNotifyTests(unittest.TestCase):
    def test_queue_prompt_notifies_immediately_without_cli_enrichment(self):
        # New prompts notify at queue time because the CLI may not be running yet
        snitchd = load_snitchd()
        calls = []
        setattr(snitchd, "CONFIG", {
            "notify_send": True,
            "notify_send_timeout": 5000,
            "pending_queue_size": 200,
            "dns_cache_max_per_source": 32768,
            "dns_cache_max_global": 131072,
            "dns_cache_refresh_workers": 32,
            "limit_rate": "3/minute",
            "burst": 5,
            "log_bucket_max_entries": 4096,
        })
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        old_notify = snitchd.notify.alert_notify
        snitchd.notify.alert_notify = lambda request, *_args: calls.append(dict(request))
        snitchd.queue.PENDING_QUESTIONS.clear()
        snitchd.queue.PENDING_PROMPT_IDS.clear()

        try:
            snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "body": b""})
        finally:
            snitchd.notify.alert_notify = old_notify

        self.assertEqual(calls, [{"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443}])

    def test_queue_full_reject_is_journal_only(self):
        # Full queues keep existing prompts and log rejected new prompts without notify-send spam
        snitchd = load_snitchd()
        events = []
        setattr(snitchd, "CONFIG", {
            "notify_send": False,
            "notify_send_timeout": 5000,
            "pending_queue_size": 1,
            "dns_cache_max_per_source": 32768,
            "dns_cache_max_global": 131072,
            "dns_cache_refresh_workers": 32,
            "limit_rate": "3/minute",
            "burst": 5,
            "log_bucket_max_entries": 4096,
        })
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"], "chat": ["10.137.0.43"]})
        snitchd.queue.PENDING_QUESTIONS.clear()
        snitchd.queue.PENDING_PROMPT_IDS.clear()
        snitchd.syslog.syslog = lambda priority, message: events.append((priority, message))

        snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "body": b""})
        snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "chat", "host": None, "dst": "5.6.7.8", "proto": "tcp", "dport": 443, "body": b""})

        self.assertEqual([request["source"] for request in snitchd.queue.PENDING_QUESTIONS.values()], ["browser"])
        self.assertIn((snitchd.syslog.LOG_INFO, "QUBES-SNITCH chat reject queue-full NET DST=5.6.7.8 PROTO=tcp DPORT=443"), events)


    def test_queue_full_reject_logs_are_rate_limited_by_source(self):
        snitchd = load_snitchd()
        events = []
        setattr(snitchd, "CONFIG", {
            "notify_send": False,
            "notify_send_timeout": 5000,
            "pending_queue_size": 1,
            "dns_cache_max_per_source": 32768,
            "dns_cache_max_global": 131072,
            "dns_cache_refresh_workers": 32,
            "limit_rate": "1/minute",
            "burst": 1,
            "log_bucket_max_entries": 4096,
        })
        setattr(snitchd, "SOURCES_BY_NAME", {"browser": ["10.137.0.42"]})
        setattr(snitchd, "LOG_BUCKETS", snitchd.OrderedDict())
        snitchd.queue.PENDING_QUESTIONS.clear()
        snitchd.queue.PENDING_PROMPT_IDS.clear()
        snitchd.syslog.syslog = lambda _priority, message: events.append(message)

        snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "body": b""})
        snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "5.6.7.8", "proto": "tcp", "dport": 443, "body": b""})
        snitchd.packet_handlers.queue_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "9.9.9.9", "proto": "tcp", "dport": 8443, "body": b""})

        self.assertEqual(len([event for event in events if "reject queue-full" in event]), 1)

    def test_log_buckets_are_capped(self):
        # Log throttle keys can include attacker-controlled DNS names, so old buckets must be evicted
        snitchd = load_snitchd()
        setattr(snitchd, "CONFIG", {"limit_rate": "1/minute", "burst": 1, "log_bucket_max_entries": 2})
        setattr(snitchd, "LOG_BUCKETS", snitchd.OrderedDict())
        snitchd.time.monotonic = lambda: 100.0

        self.assertTrue(snitchd.alerts_runtime.log_allowed(snitchd.context(), ("source", "one")))
        self.assertTrue(snitchd.alerts_runtime.log_allowed(snitchd.context(), ("source", "two")))
        self.assertTrue(snitchd.alerts_runtime.log_allowed(snitchd.context(), ("source", "three")))

        self.assertEqual(list(snitchd.LOG_BUCKETS), [("source", "two"), ("source", "three")])

    def test_alert_notify_uses_configured_expire_time(self):
        # notify-send wants milliseconds; config uses notify-send milliseconds
        snitchd = load_snitchd()
        calls = []
        old_run = snitchd.notify.subprocess.run
        snitchd.notify.subprocess.run = lambda args, check=True, timeout=None: calls.append((args, check, timeout))
        config = {"notify_send": True, "notify_send_timeout": 5000}
        request = {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443}

        try:
            snitchd.notify.alert_notify(request, config, "user", ":0", "/run/user/1000", "unix:path=/run/user/1000/bus")
        finally:
            snitchd.notify.subprocess.run = old_run

        self.assertIn("--icon=/usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg", calls[0][0])
        self.assertIn("--expire-time=5000", calls[0][0])
        self.assertIn("browser -> 1.2.3.4 tcp/443", calls[0][0])
        self.assertTrue(calls[0][1])
        self.assertEqual(calls[0][2], 1)

    def test_notify_send_timeout_propagates_as_daemon_failure(self):
        # A hung notify-send must fail the daemon instead of blocking NFQUEUE while locks are held
        snitchd = load_snitchd()
        setattr(snitchd, "CONFIG", {"notify_send": True, "notify_send_timeout": 5000})
        def hang(*_args, **_kwargs):
            raise snitchd.notify.subprocess.TimeoutExpired("notify-send", 10)
        old_notify = snitchd.notify.alert_notify
        snitchd.notify.alert_notify = hang

        try:
            with self.assertRaises(SystemExit) as caught:
                snitchd.alerts_runtime.notify_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443})
            self.assertIn("notify-send failed", str(caught.exception))
        finally:
            snitchd.notify.alert_notify = old_notify

    def test_security_notify_is_critical_and_sticky(self):
        # Security alerts ignore the optional prompt-popup setting and stay visible until dismissed
        snitchd = load_snitchd()
        calls = []
        old_run = snitchd.notify.subprocess.run
        snitchd.notify.subprocess.run = lambda args, check=True, timeout=None: calls.append((args, check, timeout))
        config = {"notify_send": False, "notify_send_timeout": 5000}

        try:
            snitchd.notify.security_notify("REJECT source IP unknown to Qubes SRC=10.137.9.9", config, "user", ":0", "/run/user/1000", "unix:path=/run/user/1000/bus")
        finally:
            snitchd.notify.subprocess.run = old_run

        self.assertIn("-u", calls[0][0])
        self.assertIn("critical", calls[0][0])
        self.assertIn("--icon=/usr/share/icons/hicolor/scalable/apps/qubes-snitch.svg", calls[0][0])
        self.assertIn("--expire-time=0", calls[0][0])
        self.assertTrue(calls[0][1])

    def test_notify_send_failure_propagates(self):
        snitchd = load_snitchd()
        def fail(_args, check=True, timeout=None):
            raise snitchd.notify.subprocess.CalledProcessError(1, "notify-send")
        old_run = snitchd.notify.subprocess.run
        snitchd.notify.subprocess.run = fail
        config = {"notify_send": True, "notify_send_timeout": 5000}
        request = {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443}

        try:
            with self.assertRaises(snitchd.notify.subprocess.CalledProcessError):
                snitchd.notify.alert_notify(request, config, "user", ":0", "/run/user/1000", "unix:path=/run/user/1000/bus")
        finally:
            snitchd.notify.subprocess.run = old_run

    def test_daemon_exits_when_notify_send_fails(self):
        snitchd = load_snitchd()
        setattr(snitchd, "CONFIG", {"notify_send": True, "notify_send_timeout": 5000})
        def fail(*_args):
            raise snitchd.notify.subprocess.CalledProcessError(1, "notify-send")
        old_notify = snitchd.notify.alert_notify
        snitchd.notify.alert_notify = fail

        try:
            with self.assertRaises(SystemExit) as caught:
                snitchd.alerts_runtime.notify_prompt(snitchd.context(), {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443})
            self.assertIn("notify-send failed", str(caught.exception))
        finally:
            snitchd.notify.alert_notify = old_notify

    def test_shipped_config_sets_notify_timeout_to_five_seconds(self):
        # Five seconds is long enough to notice but short enough not to leave stale prompts on screen
        snitchd = load_snitchd()
        config = snitchd.config.read_config(Path("templates/etc/qubes-snitch/config.yml"))

        self.assertEqual(config["notify_send_timeout"], 5000)

    def test_config_accepts_disabled_prompt_notifications(self):
        # notify_send only controls new-question popups; security alerts still notify through a separate mandatory path
        snitchd = load_snitchd()
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yml"
            path.write_text("theme: dark\nnotify_send: False\nnotify_send_timeout: 5000\npending_queue_size: 200\ndns_cache_max_per_source: 32768\ndns_cache_max_global: 131072\ndns_cache_refresh_workers: 32\ndefault_disposable_vm_name: default-dvm\nlimit_rate: 3/minute\nburst: 5\nlog_bucket_max_entries: 4096\nprompt_column_widths:\n  queue: 10\n  source: 18\n  target: 25\n  dns: 42\n  service: 22\nprompt_protocol_colors:\n  encrypted:\n    - proto: tcp\n      port: 443\n  unencrypted:\n    - proto: tcp\n      port: 80\n    - proto: udp\n      port: 53\n", encoding="utf-8")

            config = snitchd.config.read_config(path)

        self.assertIs(config["notify_send"], False)
