"""Application entry point.

Starts:
  1. Async database initialisation
  2. Telegram bot (polling mode)
  3. Background security event polling loop
  4. FastAPI HTTP server (health + admin endpoints)
"""
from __future__ import annotations

import asyncio
import logging
import logging.config

import uvicorn
from fastapi import FastAPI
from telegram.ext import Application

from app.api.routes import router
from app.collectors.base import BaseCollector
from app.collectors.paloalto import PaloAltoCollector
from app.collectors.trellix import TrellixCollector
from app.config import Settings, get_settings
from app.db import get_session_factory, init_db
from app.notifier.telegram_bot import SocBot
from app.services.access_control import AccessControl
from app.services.polling import PollingService

logger = logging.getLogger(__name__)

# Module-level singleton for polling service (accessed by API routes)
_polling_service: PollingService | None = None


def get_polling_service() -> PollingService | None:
    return _polling_service


def configure_logging(level: str) -> None:
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
            },
            "plain": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "json",
            },
        },
        "root": {
            "handlers": ["console"],
            "level": level,
        },
        "loggers": {
            "httpx": {"level": "WARNING"},
            "telegram": {"level": "WARNING"},
            "uvicorn": {"level": "WARNING"},
            "uvicorn.access": {"level": "WARNING"},
        },
    })


def build_fastapi(settings: Settings) -> FastAPI:
    app = FastAPI(
        title="Pocket SIEM Admin API",
        version="1.0.0",
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment != "production" else None,
    )
    app.include_router(router)
    return app


async def run_bot(
    settings: Settings,
    bot: SocBot,
    bot_app: Application,
) -> None:
    await bot_app.initialize()
    await bot.setup_commands()
    await bot_app.start()
    await bot_app.updater.start_polling(drop_pending_updates=True)
    logger.info("Telegram bot started (polling)")


async def run_api(settings: Settings, fastapi_app: FastAPI) -> None:
    config = uvicorn.Config(
        fastapi_app,
        host=settings.api_host,
        port=settings.api_port,
        log_level="warning",
        loop="none",
    )
    server = uvicorn.Server(config)
    logger.info("FastAPI listening on %s:%d", settings.api_host, settings.api_port)
    await server.serve()


async def main() -> None:
    global _polling_service

    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("Starting Pocket SIEM bot — %s", settings.masked_repr())

    # Database
    await init_db(settings.database_url)
    session_factory = get_session_factory(settings.database_url)

    # Access control
    access = AccessControl(set(settings.allowed_telegram_user_ids))

    # Collectors
    collectors: list[BaseCollector] = []
    if settings.enable_trellix:
        collectors.append(TrellixCollector(settings))
        logger.info("Trellix EDR collector enabled")
    if settings.enable_paloalto:
        collectors.append(PaloAltoCollector(settings))
        logger.info("Palo Alto collector enabled")
    if not collectors:
        logger.warning("No collectors enabled — bot will start but never produce alerts")

    # Telegram bot
    soc_bot = SocBot(
        settings=settings,
        access_control=access,
        session_factory=session_factory,
    )
    bot_app = soc_bot.build_application()

    # Polling service
    _polling_service = PollingService(
        settings=settings,
        collectors=collectors,
        notify_fn=soc_bot.send_alert,
        session_factory=session_factory,
    )
    # Give the bot a reference to the poller for /pause /resume /status
    soc_bot._polling = _polling_service

    # FastAPI
    fastapi_app = build_fastapi(settings)

    # Start everything concurrently
    await run_bot(settings, soc_bot, bot_app)
    _polling_service.start()

    try:
        await run_api(settings, fastapi_app)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutdown signal received")
    finally:
        logger.info("Shutting down…")
        _polling_service.stop()
        await bot_app.updater.stop()
        await bot_app.stop()
        await bot_app.shutdown()
        logger.info("Shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
