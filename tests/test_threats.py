from pyshield.threats import assess_connection


def test_normal_connection_is_info():
    result = assess_connection("192.0.2.10", 443, "ALLOW", False)
    assert result.level == "INFO"
    assert result.score == 0


def test_review_port_is_low_not_automatically_blocked():
    result = assess_connection("192.0.2.10", 3389, "ALLOW", False)
    assert result.level == "LOW"
    assert result.score == 25


def test_burst_is_medium():
    result = assess_connection("192.0.2.10", 443, "ALLOW", True)
    assert result.level == "MEDIUM"
    assert result.score == 60


def test_block_rule_is_high():
    result = assess_connection("203.0.113.25", 443, "BLOCK", False)
    assert result.level == "HIGH"
    assert result.score == 100
