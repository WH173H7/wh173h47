from pyshield.detector import BurstDetector


def test_persistent_connection_is_not_counted_repeatedly():
    detector = BurstDetector(
        threshold=2,
        window_seconds=10,
        seen_ttl=30
    )

    assert detector.observe("198.51.100.10", "conn-1") is False
    assert detector.observe("198.51.100.10", "conn-1") is False


def test_two_new_connections_can_trigger_burst():
    detector = BurstDetector(
        threshold=2,
        window_seconds=10,
        seen_ttl=30
    )

    assert detector.observe("198.51.100.10", "conn-1") is False
    assert detector.observe("198.51.100.10", "conn-2") is True
