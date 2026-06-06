"""Telegram message formatters for each vendor's SecurityEvent."""
from __future__ import annotations

from app.models import SecurityEvent
from app.severity import Severity


def _fmt_field(label: str, value: str | None, bold: bool = False) -> str:
    if not value:
        return ""
    val = f"*{value}*" if bold else value
    return f"• *{label}:* {val}\n"


def _dt(event: SecurityEvent) -> str:
    if event.detection_time:
        return event.detection_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    return "Unknown"


def format_trellix(event: SecurityEvent) -> str:
    sev = Severity.from_str(event.severity)
    header = f"🚨 *Trellix EDR Alert* {sev.emoji()}\n"
    body = (
        f"• *Severity:* `{sev.label()}`\n"
        f"{_fmt_field('Host', event.host)}"
        f"{_fmt_field('User', event.username)}"
        f"{_fmt_field('Detection', event.title)}"
        f"{_fmt_field('Process', event.process_name)}"
        f"{_fmt_field('Command', event.command_line)}"
        f"{_fmt_field('MITRE', f'{event.tactic} / {event.technique}' if event.tactic or event.technique else None)}"
        f"{_fmt_field('Status', event.status)}"
        f"• *Time:* `{_dt(event)}`\n"
    )
    return header + body


def format_paloalto(event: SecurityEvent) -> str:
    sev = Severity.from_str(event.severity)
    dst_info: str | None = None
    if event.destination_ip:
        dst_info = event.destination_ip
        if event.destination_port:
            dst_info += f":{event.destination_port}"
    header = f"🔥 *Palo Alto Threat Alert* {sev.emoji()}\n"
    body = (
        f"• *Severity:* `{sev.label()}`\n"
        f"{_fmt_field('Threat', event.threat_name or event.title)}"
        f"{_fmt_field('Type', event.threat_type)}"
        f"{_fmt_field('Source', event.source_ip)}"
        f"{_fmt_field('Destination', dst_info)}"
        f"{_fmt_field('User', event.source_user)}"
        f"{_fmt_field('App', event.application)}"
        f"{_fmt_field('Action', event.action)}"
        f"{_fmt_field('Rule', event.rule)}"
        f"{_fmt_field('URL/Domain', event.url_or_domain)}"
        f"• *Time:* `{_dt(event)}`\n"
    )
    return header + body


def format_event(event: SecurityEvent) -> str:
    """Dispatch to the correct formatter based on vendor."""
    if event.vendor.lower().startswith("trellix"):
        return format_trellix(event)
    if event.vendor.lower().startswith("palo"):
        return format_paloalto(event)
    # Generic fallback
    sev = Severity.from_str(event.severity)
    return (
        f"⚠️ *Security Alert* {sev.emoji()}\n"
        f"• *Vendor:* {event.vendor}\n"
        f"• *Severity:* `{sev.label()}`\n"
        f"• *Title:* {event.title}\n"
        f"• *Time:* `{_dt(event)}`\n"
    )
