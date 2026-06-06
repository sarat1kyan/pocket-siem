"""Tests for severity parsing and comparison."""
from app.severity import Severity


def test_from_str_known_values():
    assert Severity.from_str("high") == Severity.HIGH
    assert Severity.from_str("CRITICAL") == Severity.CRITICAL
    assert Severity.from_str("medium") == Severity.MEDIUM
    assert Severity.from_str("low") == Severity.LOW
    assert Severity.from_str("informational") == Severity.INFORMATIONAL


def test_from_str_aliases():
    assert Severity.from_str("crit") == Severity.CRITICAL
    assert Severity.from_str("fatal") == Severity.CRITICAL
    assert Severity.from_str("med") == Severity.MEDIUM
    assert Severity.from_str("info") == Severity.INFORMATIONAL


def test_from_str_panos_numbers():
    assert Severity.from_str("5") == Severity.CRITICAL
    assert Severity.from_str("4") == Severity.HIGH
    assert Severity.from_str("3") == Severity.MEDIUM
    assert Severity.from_str("2") == Severity.LOW
    assert Severity.from_str("1") == Severity.INFORMATIONAL


def test_from_str_unknown():
    assert Severity.from_str("garbage") == Severity.UNKNOWN
    assert Severity.from_str(None) == Severity.UNKNOWN
    assert Severity.from_str("") == Severity.UNKNOWN


def test_meets_threshold():
    assert Severity.CRITICAL.meets_threshold(Severity.HIGH)
    assert Severity.HIGH.meets_threshold(Severity.HIGH)
    assert not Severity.MEDIUM.meets_threshold(Severity.HIGH)
    assert not Severity.LOW.meets_threshold(Severity.CRITICAL)


def test_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFORMATIONAL


def test_label():
    assert Severity.HIGH.label() == "HIGH"
    assert Severity.CRITICAL.label() == "CRITICAL"


def test_emoji():
    assert Severity.CRITICAL.emoji() == "🔴"
    assert Severity.HIGH.emoji() == "🟠"
