"""Severity constants and comparison utilities."""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def from_str(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        mapping = {
            "informational": cls.INFORMATIONAL,
            "info": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "fatal": cls.CRITICAL,
            # Palo Alto numeric strings
            "1": cls.INFORMATIONAL,
            "2": cls.LOW,
            "3": cls.MEDIUM,
            "4": cls.HIGH,
            "5": cls.CRITICAL,
        }
        return mapping.get(str(value).lower().strip(), cls.UNKNOWN)

    def label(self) -> str:
        return self.name.upper()

    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFORMATIONAL: "⚪",
            Severity.UNKNOWN: "❓",
        }[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        return self >= threshold
