# Purpose: regression tests for pending prompt races
# Scope: stale CLI answers must not create rules after queue cleanup removes a prompt
import threading
import unittest

from qubes_snitch import queue


class QueueRuntimeTests(unittest.TestCase):
    def setUp(self):
        queue.PENDING_QUESTIONS.clear()
        queue.PENDING_PROMPT_IDS.clear()

    def tearDown(self):
        queue.PENDING_QUESTIONS.clear()
        queue.PENDING_PROMPT_IDS.clear()

    def test_cleaned_up_prompt_is_rechecked_after_waiting_for_policy_lock(self):
        # Source cleanup can remove a prompt while the CLI answer waits to save policy
        key = ("disp1234", "net", "1.2.3.4", "tcp", 443)
        request = {"source": "disp1234", "dst": "1.2.3.4", "proto": "tcp", "dport": 443}
        queue.PENDING_QUESTIONS[key] = dict(request)
        entered_lock = threading.Event()
        release_lock = threading.Event()
        saved = []

        class GateLock:
            def __enter__(self):
                # Signal after the stale-decision precheck but before append_rule can run
                entered_lock.set()
                release_lock.wait(timeout=5)

            def __exit__(self, _exc_type, _exc, _tb):
                return False

        thread = threading.Thread(
            target=queue.save_pending_decision,
            args=(key, request, "allow", GateLock(), lambda _request, _decision: saved.append("append"), lambda: saved.append("load")),
        )
        thread.start()
        self.assertTrue(entered_lock.wait(timeout=5))
        with queue.PENDING_CONDITION:
            del queue.PENDING_QUESTIONS[key]
        release_lock.set()
        thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(saved, [])
        self.assertNotIn(key, queue.PENDING_QUESTIONS)

    def test_reused_prompt_key_does_not_accept_old_cli_answer(self):
        # Numbered DispVM names can be reused, so a new same-key prompt must not accept an old CLI answer
        request = {"source": "disp1234", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "body": b""}
        config = {"pending_queue_size": 10}
        saved = []
        queue.queue_question(request, config, lambda _request: None, lambda _request: None)
        key, old_cli_request = queue.next_pending_request()
        queue.remove_pending_for_source("disp1234")
        queue.queue_question(request, config, lambda _request: None, lambda _request: None)

        queue.save_pending_decision(key, old_cli_request, "allow", threading.Lock(), lambda _request, _decision: saved.append("append"), lambda: saved.append("load"))

        self.assertEqual(saved, [])
        self.assertIn(key, queue.PENDING_QUESTIONS)


    def test_hostname_decision_removes_already_queued_sibling_ips(self):
        # If two IPs from the same A record are already queued, answering A/R once must not prompt the sibling next
        current_key = ("app-signal", "net", "76.223.66.180", "tcp", 443)
        sibling_key = ("app-signal", "net", "15.197.251.99", "tcp", 443)
        other_port_key = ("app-signal", "net", "15.197.251.99", "tcp", 80)
        request = {"_prompt_id": 1, "source": "app-signal", "host": "A grpc.chat.signal.org", "dst": "76.223.66.180", "proto": "tcp", "dport": 443, "body": b""}
        queue.PENDING_QUESTIONS[current_key] = dict(request)
        queue.PENDING_PROMPT_IDS[current_key] = 1
        queue.PENDING_QUESTIONS[sibling_key] = {"source": "app-signal", "host": "A grpc.chat.signal.org", "dst": "15.197.251.99", "proto": "tcp", "dport": 443, "body": b""}
        queue.PENDING_PROMPT_IDS[sibling_key] = 2
        queue.PENDING_QUESTIONS[other_port_key] = {"source": "app-signal", "host": "A grpc.chat.signal.org", "dst": "15.197.251.99", "proto": "tcp", "dport": 80, "body": b""}
        queue.PENDING_PROMPT_IDS[other_port_key] = 3
        saved = []

        original_resolve = queue.snitch_config.resolve_dest_dns
        self.addCleanup(lambda: setattr(queue.snitch_config, "resolve_dest_dns", original_resolve))
        queue.snitch_config.resolve_dest_dns = lambda _path, _hostname: ["15.197.251.99", "76.223.66.180"]

        queue.save_pending_decision(current_key, request, "allow-dns", threading.Lock(), lambda _request, _decision: saved.append("append"), lambda: saved.append("load"))

        self.assertEqual(saved, ["append", "load"])
        self.assertNotIn(current_key, queue.PENDING_QUESTIONS)
        self.assertNotIn(sibling_key, queue.PENDING_QUESTIONS)
        self.assertIn(other_port_key, queue.PENDING_QUESTIONS)


    def test_full_queue_rejects_new_prompt_without_evicting_existing(self):
        config = {"pending_queue_size": 1}
        first = {"source": "browser", "host": None, "dst": "1.2.3.4", "proto": "tcp", "dport": 443, "body": b""}
        second = {"source": "chat", "host": None, "dst": "5.6.7.8", "proto": "tcp", "dport": 443, "body": b""}
        events = []

        self.assertEqual(queue.queue_question(first, config, lambda request: events.append(("pending", request["source"])), lambda request: events.append(("full", request["source"]))), "queued")
        self.assertEqual(queue.queue_question(second, config, lambda request: events.append(("pending", request["source"])), lambda request: events.append(("full", request["source"]))), "full")

        self.assertEqual(events, [("pending", "browser"), ("full", "chat")])
        self.assertEqual([request["source"] for request in queue.PENDING_QUESTIONS.values()], ["browser"])


if __name__ == "__main__":
    unittest.main()
