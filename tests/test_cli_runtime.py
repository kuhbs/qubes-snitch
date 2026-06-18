# Purpose: regression tests for terminal CLI startup and daemon-connection failures
# Scope: catches user-facing crashes before the CLI reaches the daemon socket
import unittest

from snitch_testlib import load_cli


class CliRuntimeTests(unittest.TestCase):
    def test_cli_lock_permission_error_reports_daemon_not_running(self):
        # systemd owns /run/qubes-snitch, so a missing runtime directory must not become a traceback for users
        cli = load_cli()

        class FakeParent:
            def mkdir(self, *_args, **_kwargs):
                raise PermissionError("no permission to create runtime dir")

        class FakeLockFile:
            parent = FakeParent()

        original_lock_file = cli.LOCK_FILE
        setattr(cli, "LOCK_FILE", FakeLockFile())
        try:
            with self.assertRaises(SystemExit) as caught:
                cli.acquire_cli_lock()
        finally:
            setattr(cli, "LOCK_FILE", original_lock_file)

        self.assertEqual(str(caught.exception), "qubes-snitchd is not running")
