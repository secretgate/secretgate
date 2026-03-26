"""Tests for runtime statistics tracking."""

import threading

from secretgate.stats import Stats


class TestStats:
    def test_initial_state(self):
        stats = Stats()
        snap = stats.snapshot()
        assert snap["requests_scanned"] == 0
        assert snap["secrets_found"] == 0
        assert snap["requests_blocked"] == 0
        assert snap["by_service"] == {}
        assert snap["uptime_seconds"] >= 0

    def test_record_scan_no_secrets(self):
        stats = Stats()
        stats.record_scan(secrets=0, mode="redact")
        snap = stats.snapshot()
        assert snap["requests_scanned"] == 1
        assert snap["secrets_found"] == 0
        assert snap["requests_redacted"] == 0

    def test_record_scan_with_secrets_redact(self):
        stats = Stats()
        stats.record_scan(secrets=3, mode="redact", services=["aws", "github", "aws"])
        snap = stats.snapshot()
        assert snap["requests_scanned"] == 1
        assert snap["secrets_found"] == 3
        assert snap["requests_redacted"] == 1
        assert snap["by_service"]["aws"] == 2
        assert snap["by_service"]["github"] == 1

    def test_record_scan_blocked(self):
        stats = Stats()
        stats.record_scan(secrets=1, mode="block", services=["openai"])
        snap = stats.snapshot()
        assert snap["requests_blocked"] == 1

    def test_record_scan_audit(self):
        stats = Stats()
        stats.record_scan(secrets=2, mode="audit")
        snap = stats.snapshot()
        assert snap["requests_audited"] == 1

    def test_record_packfile(self):
        stats = Stats()
        stats.record_packfile(blocked=False)
        stats.record_packfile(blocked=True)
        snap = stats.snapshot()
        assert snap["packfiles_scanned"] == 2
        assert snap["packfiles_blocked"] == 1

    def test_reset(self):
        stats = Stats()
        stats.record_scan(secrets=5, mode="redact", services=["aws"])
        stats.reset()
        snap = stats.snapshot()
        assert snap["requests_scanned"] == 0
        assert snap["secrets_found"] == 0
        assert snap["by_service"] == {}

    def test_thread_safety(self):
        stats = Stats()
        errors = []

        def worker():
            try:
                for _ in range(100):
                    stats.record_scan(secrets=1, mode="redact", services=["test"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        snap = stats.snapshot()
        assert snap["requests_scanned"] == 1000
        assert snap["secrets_found"] == 1000

    def test_snapshot_returns_copy(self):
        stats = Stats()
        stats.record_scan(secrets=1, mode="redact", services=["aws"])
        snap1 = stats.snapshot()
        stats.record_scan(secrets=2, mode="block", services=["github"])
        snap2 = stats.snapshot()
        # snap1 should not be modified by the second record
        assert snap1["requests_scanned"] == 1
        assert snap2["requests_scanned"] == 2
