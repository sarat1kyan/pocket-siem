"""Telegram bot — commands, access control, and proactive notifications."""
from __future__ import annotations

import logging

from sqlalchemy import desc, select
from telegram import BotCommand, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from app.config import Settings
from app.models import SecurityEvent, SecurityEventORM
from app.notifier.formatters import format_event
from app.services.access_control import AccessControl
from app.severity import Severity

logger = logging.getLogger(__name__)


def _guard(access: AccessControl):
    """Decorator factory — reject unknown users before running a handler."""
    def decorator(fn):
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not access.check(update):
                await update.effective_message.reply_text(
                    "⛔ Access denied. Use /whoami to find your Telegram ID "
                    "and ask the administrator to add you."
                )
                return
            return await fn(update, context)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


class SocBot:
    def __init__(
        self,
        settings: Settings,
        access_control: AccessControl,
        session_factory,
        polling_service=None,
    ) -> None:
        self._settings = settings
        self._access = access_control
        self._session_factory = session_factory
        self._polling = polling_service
        self._app: Application | None = None

    def _guard(self, fn):
        return _guard(self._access)(fn)

    def build_application(self) -> Application:
        app = (
            Application.builder()
            .token(self._settings.telegram_bot_token)
            .build()
        )

        g = self._guard

        app.add_handler(CommandHandler("start", g(self._cmd_start)))
        app.add_handler(CommandHandler("help", g(self._cmd_help)))
        app.add_handler(CommandHandler("status", g(self._cmd_status)))
        app.add_handler(CommandHandler("health", g(self._cmd_health)))
        app.add_handler(CommandHandler("sources", g(self._cmd_sources)))
        app.add_handler(CommandHandler("recent", g(self._cmd_recent)))
        app.add_handler(CommandHandler("recent_trellix", g(self._cmd_recent_trellix)))
        app.add_handler(CommandHandler("recent_paloalto", g(self._cmd_recent_paloalto)))
        app.add_handler(CommandHandler("critical", g(self._cmd_critical)))
        app.add_handler(CommandHandler("set_severity", g(self._cmd_set_severity)))
        app.add_handler(CommandHandler("pause", g(self._cmd_pause)))
        app.add_handler(CommandHandler("resume", g(self._cmd_resume)))
        app.add_handler(CommandHandler("whoami", self._cmd_whoami))  # no guard — always works
        app.add_handler(
            MessageHandler(filters.COMMAND, g(self._cmd_unknown))
        )

        self._app = app
        return app

    async def setup_commands(self) -> None:
        if self._app is None:
            return
        await self._app.bot.set_my_commands([
            BotCommand("start", "Welcome message"),
            BotCommand("help", "List all commands"),
            BotCommand("status", "Bot and poller status"),
            BotCommand("health", "Upstream API health"),
            BotCommand("sources", "Configured data sources"),
            BotCommand("recent", "Last 5 alerts (all sources)"),
            BotCommand("recent_trellix", "Last 5 Trellix alerts"),
            BotCommand("recent_paloalto", "Last 5 Palo Alto alerts"),
            BotCommand("critical", "Last 5 CRITICAL events"),
            BotCommand("set_severity", "Set min severity (high|critical|medium|low)"),
            BotCommand("pause", "Pause alert notifications"),
            BotCommand("resume", "Resume alert notifications"),
            BotCommand("whoami", "Show your Telegram user ID"),
        ])

    async def send_alert(self, event: SecurityEvent) -> None:
        """Push a formatted security alert to the configured chat or all allowed users."""
        if self._app is None:
            logger.error("Cannot send alert — bot application not initialised")
            return
        text = format_event(event)
        targets: list[int] = []
        if self._settings.telegram_chat_id:
            targets.append(self._settings.telegram_chat_id)
        else:
            targets.extend(self._access.list_users())
        for chat_id in targets:
            try:
                await self._app.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode=ParseMode.MARKDOWN,
                )
            except Exception as exc:
                logger.error("Failed to send alert to chat_id=%d: %s", chat_id, exc)

    # ── Command handlers ──────────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "👋 *Pocket SIEM Bot* is running!\n\n"
            "I monitor Trellix EDR and Palo Alto firewall events and alert you about "
            "high-severity threats.\n\nUse /help to see all commands.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        text = (
            "*Available Commands*\n\n"
            "/status — Bot and poller status\n"
            "/health — Check upstream API health\n"
            "/sources — List configured data sources\n"
            "/recent — Last 5 alerts (all sources)\n"
            "/recent\\_trellix — Last 5 Trellix alerts\n"
            "/recent\\_paloalto — Last 5 Palo Alto alerts\n"
            "/critical — Last 5 CRITICAL events\n"
            "/set\\_severity high|critical|medium|low — Change threshold\n"
            "/pause — Pause notifications\n"
            "/resume — Resume notifications\n"
            "/whoami — Show your Telegram user ID\n"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        paused = self._polling.paused if self._polling else False
        threshold = self._polling._threshold.label() if self._polling else self._settings.min_severity.upper()
        mock = "🟡 MOCK MODE" if self._settings.mock_mode else "🟢 Live"
        text = (
            f"*Bot Status*\n\n"
            f"• Mode: {mock}\n"
            f"• Polling: {'⏸ Paused' if paused else '▶️ Active'}\n"
            f"• Min severity: `{threshold}`\n"
            f"• Poll interval: `{self._settings.poll_interval_seconds}s`\n"
            f"• Trellix: {'✅ Enabled' if self._settings.enable_trellix else '❌ Disabled'}\n"
            f"• Palo Alto: {'✅ Enabled' if self._settings.enable_paloalto else '❌ Disabled'}\n"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_health(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        from app.collectors.paloalto import PaloAltoCollector
        from app.collectors.trellix import TrellixCollector

        lines = ["*Health Check*\n"]
        if self._settings.enable_trellix:
            ok = await TrellixCollector(self._settings).health_check()
            lines.append(f"• Trellix EDR: {'✅ OK' if ok else '❌ Unreachable'}")
        if self._settings.enable_paloalto:
            ok = await PaloAltoCollector(self._settings).health_check()
            lines.append(f"• Palo Alto: {'✅ OK' if ok else '❌ Unreachable'}")
        if not lines[1:]:
            lines.append("• No sources enabled")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    async def _cmd_sources(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        lines = ["*Configured Sources*\n"]
        if self._settings.enable_trellix:
            lines.append(f"• Trellix EDR: `{self._settings.trellix_base_url}`")
        else:
            lines.append("• Trellix EDR: ❌ disabled")
        if self._settings.enable_paloalto:
            host = self._settings.paloalto_hostname or "not configured"
            lines.append(f"• Palo Alto: `{host}` (vsys: {self._settings.paloalto_vsys})")
        else:
            lines.append("• Palo Alto: ❌ disabled")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    async def _cmd_recent(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor=None, limit=5)

    async def _cmd_recent_trellix(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor="Trellix", limit=5)

    async def _cmd_recent_paloalto(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor="PaloAlto", limit=5)

    async def _cmd_critical(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._send_recent(update, vendor=None, limit=5, severity="critical")

    async def _send_recent(
        self,
        update: Update,
        vendor: str | None,
        limit: int = 5,
        severity: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            stmt = select(SecurityEventORM).order_by(desc(SecurityEventORM.received_at)).limit(limit)
            if vendor:
                stmt = stmt.where(SecurityEventORM.vendor == vendor)
            if severity:
                stmt = stmt.where(SecurityEventORM.severity == severity)
            result = await session.execute(stmt)
            rows = result.scalars().all()

        if not rows:
            await update.message.reply_text("No events found.")
            return
        for row in rows:
            dt = row.detection_time or row.received_at
            ts = dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "unknown"
            sev = Severity.from_str(row.severity)
            text = (
                f"{sev.emoji()} *{row.vendor}* — `{sev.label()}`\n"
                f"• {row.title}\n"
                f"• `{ts}`"
            )
            await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_set_severity(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        args = context.args
        valid = {"low", "medium", "high", "critical"}
        if not args or args[0].lower() not in valid:
            await update.message.reply_text(
                f"Usage: /set_severity <level>\nValid levels: {', '.join(sorted(valid))}"
            )
            return
        level = args[0].lower()
        if self._polling:
            self._polling.set_threshold(level)
        await update.message.reply_text(
            f"✅ Severity threshold updated to `{level.upper()}`",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_pause(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if self._polling:
            self._polling.pause()
        await update.message.reply_text("⏸ Alert notifications paused. Use /resume to re-enable.")

    async def _cmd_resume(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if self._polling:
            self._polling.resume()
        await update.message.reply_text("▶️ Alert notifications resumed.")

    async def _cmd_whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None:
            await update.message.reply_text("Unable to determine your identity.")
            return
        await update.message.reply_text(
            f"👤 *Your Telegram Identity*\n\n"
            f"• ID: `{user.id}`\n"
            f"• Username: @{user.username or 'none'}\n"
            f"• Name: {user.full_name}\n\n"
            f"To gain access, ask the admin to add your ID (`{user.id}`) "
            f"to `ALLOWED_TELEGRAM_USER_IDS` in the bot configuration.",
            parse_mode=ParseMode.MARKDOWN,
        )

    async def _cmd_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text(
            "Unknown command. Use /help to see available commands."
        )
