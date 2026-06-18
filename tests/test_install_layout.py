# Purpose: regression tests for shipped install paths, service files, and config layout
# Scope: catches packaging/install contract drift without booting a Qubes VM
import unittest

import yaml

from snitch_testlib import INSTALL_DOM0_SH, INSTALL_SH, REPO, SNITCH_CLI, load_snitchd


class InstallLayoutTests(unittest.TestCase):
    # Install-layout tests protect paths that users, systemd, qvm-appmenus, and README commands rely on
    def test_cli_payload_uses_user_bin_path(self):
        # The installed CLI path must stay /usr/bin/qubes-snitch because the launcher and README call it
        install_script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertTrue((REPO / "qubes-snitchd.py").exists())
        self.assertTrue(SNITCH_CLI.exists())
        self.assertIn("/usr/bin/qubes-snitch", install_script)
        self.assertIn("qubes-snitch.py", install_script)
        self.assertIn("qubes-snitchd.py", install_script)
        self.assertIn("/usr/lib/python3/dist-packages/qubes_snitch", install_script)
        self.assertIn("qubes_snitch/*.py", install_script)

    def test_notify_send_is_enabled_in_shipped_config(self):
        # Prompt notifications are enabled by default, while security alerts ignore this optional prompt setting
        config_file = REPO / "templates/etc/qubes-snitch/config.yml"
        config_text = config_file.read_text(encoding="utf-8")
        config = yaml.safe_load(config_text)

        self.assertIs(config["notify_send"], True)
        self.assertIn("security alerts always use notify-send", config_text)

    def test_desktop_launcher_uses_xfce_terminal(self):
        # The desktop launcher must open the terminal CLI because prompts are line-based
        desktop_file = REPO / "templates/usr/share/applications/qubes-snitch.desktop"
        desktop = desktop_file.read_text(encoding="utf-8")
        install_script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertTrue(desktop_file.exists())
        self.assertIn("Name=Qubes Snitch", desktop)
        self.assertIn("Exec=/usr/bin/xfce4-terminal --title=Qubes-Snitch --command=/usr/bin/qubes-snitch", desktop)
        self.assertIn("Terminal=false", desktop)
        self.assertIn("xfce4-terminal", install_script)
        self.assertIn("/usr/share/applications/qubes-snitch.desktop", install_script)

    def test_systemd_service_runs_in_qubes_proxyvm(self):
        # The daemon should only run in a network-providing ProxyVM, not in a plain AppVM/template
        service = (REPO / "templates/etc/systemd/system/qubes-snitchd.service").read_text(encoding="utf-8")

        self.assertIn('$(/usr/bin/qubesdb-read /qubes-vm-type)', service)
        self.assertIn('= "ProxyVM"', service)
        self.assertIn('Requires=qubes-snitch-fail-closed.service qubes-iptables.service qubes-network.service qubes-firewall.service', service)
        self.assertIn('After=qubes-snitch-fail-closed.service qubes-iptables.service qubes-network.service qubes-firewall.service network-online.target', service)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_SETUID CAP_SETGID', service.splitlines())
        self.assertIn('Restart=no', service)

    def test_systemd_service_loads_static_fail_closed_table_first(self):
        # systemd must install a minimal reject table before Python can fail on config, rules, or qrexec
        service = (REPO / "templates/etc/systemd/system/qubes-snitchd.service").read_text(encoding="utf-8")
        nft = (REPO / "templates/usr/lib/qubes-snitch/fail-closed.nft").read_text(encoding="utf-8")
        stop_post_path = REPO / "templates/usr/lib/qubes-snitch/stop-post.sh"
        stop_post = stop_post_path.read_text(encoding="utf-8")
        install_script = INSTALL_SH.read_text(encoding="utf-8")

        self.assertEqual(stop_post_path.stat().st_mode & 0o777, 0o755)
        self.assertIn("ExecStartPre=/usr/sbin/nft -f /usr/lib/qubes-snitch/fail-closed.nft", service)
        self.assertIn("ExecStopPost=/usr/lib/qubes-snitch/stop-post.sh", service)
        self.assertIn("/usr/sbin/nft -f /usr/lib/qubes-snitch/fail-closed.nft", stop_post)
        self.assertIn('[ "$SERVICE_RESULT" != success ]', stop_post)
        self.assertIn("RuntimeDirectory=qubes-snitch", service)
        self.assertIn("RuntimeDirectoryMode=0750", service)
        self.assertIn("/usr/lib/qubes-snitch/fail-closed.nft", install_script)
        self.assertIn("install -m 0755 templates/usr/lib/qubes-snitch/stop-post.sh", install_script)
        self.assertIn("meta nfproto ipv4", nft)
        self.assertIn("chain input", nft)
        self.assertIn('iifname "vif*"', nft)
        self.assertIn("fib daddr type local", nft)
        self.assertIn("QUBES-SNITCH local reject", nft)

    def test_daemon_startup_does_not_load_fail_closed_from_python(self):
        # systemd owns fail-closed start/stop; Python daemon starts after ExecStartPre already loaded it
        snitchd = load_snitchd()
        events = []
        snitchd.RULES_DIR = REPO / ".test-rules-dir"
        snitchd.setup_run_dir = lambda: events.append("run-dir")
        snitchd.signal.signal = lambda *_args: None
        snitchd.policy_runtime.load_policy_without_sources = lambda _ctx: events.append("policy")
        snitchd.policy_runtime.load_fail_closed_nft = lambda _ctx: events.append("fail-closed")
        snitchd.open_socket = lambda: events.append("socket")
        original_thread = snitchd.threading.Thread
        snitchd.threading.Thread = lambda target, daemon: type("FakeThread", (), {"start": lambda self: events.append("thread")})()
        snitchd.sources_runtime.refresh_sources_required = lambda _ctx: events.append("sources")
        snitchd.run_queues = lambda: (_ for _ in ()).throw(SystemExit(0))

        try:
            with self.assertRaises(SystemExit):
                snitchd.main()
        finally:
            snitchd.threading.Thread = original_thread

        self.assertLess(events.index("policy"), events.index("socket"))
        if snitchd.RULES_DIR.exists():
            snitchd.RULES_DIR.rmdir()

    def test_dom0_installer_creates_live_source_identity_service(self):
        # The dom0 installer owns qrexec policy, service setup, ProxyVM creation, and README entrypoints
        installer = INSTALL_DOM0_SH.read_text(encoding="utf-8")
        readme = (REPO / "README.md").read_text(encoding="utf-8")

        self.assertTrue(INSTALL_DOM0_SH.exists())
        self.assertIn("chmod 700 install-dom0.sh", readme)
        self.assertIn("./install-dom0.sh", readme)
        self.assertIn("if qvm-check --quiet \"$SNITCH_TEMPLATE\"; then", installer)
        self.assertIn("elif qvm-check --quiet \"$SNITCH_VM\"; then", installer)
        self.assertIn("sudo tee \"$RPC_POLICY\" >/dev/null <<EOF", installer)
        self.assertIn("qvm-service \"$SNITCH_VM\" qubes-network on", installer)
        self.assertIn("qvm-service \"$SNITCH_VM\" qubes-firewall on", installer)
        self.assertIn("/etc/qubes-rpc/$RPC_SERVICE", installer)
        self.assertIn("$RPC_SERVICE * $SNITCH_VM @adminvm allow", installer)
        self.assertIn("qvm-appmenus --update --force \"$SNITCH_VM\"", installer)
        self.assertIn("qvm-shutdown --wait \"$SNITCH_TEMPLATE\"", installer)
        self.assertIn("Refer to README.md for how to continue from here", installer)
        self.assertIn("qvm-ls --raw-data --fields NAME,IP,LABEL,CLASS,TEMPLATE", installer)
        self.assertIn('[ "$name" = dom0 ] && continue', installer)
        self.assertIn('[ -n "$ip" ] && [ "$ip" != "-" ] || continue', installer)
        self.assertIn("live dom0 qrexec lookup", readme)
        self.assertIn("VM name | IP address | label color | VM class | template", readme)
        self.assertIn("qvm-run sys-snitch 'xfce4-terminal --command /usr/bin/qubes-snitch'", readme)

    def test_systemd_stop_post_fails_if_fail_closed_restore_fails(self):
        # Stop-time fail-closed restore must be visible to systemd instead of hidden by a later notification command
        stop_post = (REPO / "templates/usr/lib/qubes-snitch/stop-post.sh").read_text(encoding="utf-8")

        self.assertIn("/usr/sbin/nft -f /usr/lib/qubes-snitch/fail-closed.nft || rc=$?", stop_post)
        self.assertIn('exit "$rc"', stop_post)

    def test_systemd_stop_post_notifies_when_fail_closed_restore_fails(self):
        # nft restore failures must keep their nonzero status and still attempt the critical desktop alert
        stop_post = (REPO / "templates/usr/lib/qubes-snitch/stop-post.sh").read_text(encoding="utf-8")

        self.assertIn("/usr/sbin/nft -f /usr/lib/qubes-snitch/fail-closed.nft || rc=$?", stop_post)
        self.assertIn('[ "$rc" -ne 0 ] || [ "$SERVICE_RESULT" != success ]', stop_post)
        self.assertIn('notify-send -u critical', stop_post)
