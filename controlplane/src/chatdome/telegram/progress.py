"""Compact edit-in-place progress feedback for Telegram operations."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class TelegramProgressMessage:
    """Own one Telegram status message and update it without adding chat noise."""

    def __init__(
        self,
        message: Any,
        *,
        symbol: str,
        label: str,
        update_interval: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        started_at: float | None = None,
        edit_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self._symbol = self._compact(symbol)
        self._label = self._compact(label)
        self._update_interval = max(0.05, float(update_interval))
        self._clock = clock
        self._started_at = clock() if started_at is None else started_at
        self._metric_mode = "elapsed"
        self._progress: tuple[int, int] | None = None
        self._last_text = ""
        self._edit_kwargs = dict(edit_kwargs or {})
        self._ticker: asyncio.Task | None = None
        self._edit_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def create(
        cls,
        target: Any,
        *,
        symbol: str,
        label: str,
        update_interval: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        edit_kwargs: dict[str, Any] | None = None,
    ) -> "TelegramProgressMessage":
        started_at = clock()
        initial_text = cls.format_line(symbol, label)
        message = await target.reply_text(initial_text)
        progress = cls(
            message,
            symbol=symbol,
            label=label,
            update_interval=update_interval,
            clock=clock,
            started_at=started_at,
            edit_kwargs=edit_kwargs,
        )
        progress._last_text = initial_text
        progress._start_ticker()
        return progress

    @classmethod
    async def attach(
        cls,
        message: Any,
        *,
        symbol: str,
        label: str,
        update_interval: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        edit_kwargs: dict[str, Any] | None = None,
    ) -> "TelegramProgressMessage":
        progress = cls(
            message,
            symbol=symbol,
            label=label,
            update_interval=update_interval,
            clock=clock,
            edit_kwargs=edit_kwargs,
        )
        if not await progress._edit(include_metric=False):
            raise RuntimeError("Telegram progress message could not be initialized")
        progress._start_ticker()
        return progress

    @staticmethod
    def _compact(value: Any) -> str:
        return " ".join(str(value or "").split()).strip()

    @classmethod
    def format_line(
        cls,
        symbol: str,
        label: str,
        *,
        elapsed_seconds: int | None = None,
        progress: tuple[int, int] | None = None,
    ) -> str:
        base = " ".join(
            part for part in (cls._compact(symbol), cls._compact(label)) if part
        )
        if progress is not None:
            current, total = progress
            if total > 0:
                return f"{base} · {max(0, current)}/{total}"
        if elapsed_seconds is not None and elapsed_seconds > 0:
            return f"{base} · {elapsed_seconds} 秒"
        return base

    def _start_ticker(self) -> None:
        if self._ticker is None:
            self._ticker = asyncio.create_task(self._ticker_loop())

    async def _ticker_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._update_interval)
                await self.refresh()
        except asyncio.CancelledError:
            raise

    def _render(self, *, include_metric: bool = True) -> str:
        elapsed = None
        progress = None
        if include_metric and self._metric_mode == "elapsed":
            elapsed = max(0, int(self._clock() - self._started_at))
        elif include_metric and self._metric_mode == "progress":
            progress = self._progress
        return self.format_line(
            self._symbol,
            self._label,
            elapsed_seconds=elapsed,
            progress=progress,
        )

    async def _edit(self, *, include_metric: bool = True) -> bool:
        if self._closed:
            return False
        text = self._render(include_metric=include_metric)
        async with self._edit_lock:
            if self._closed or text == self._last_text:
                return False
            try:
                await self.message.edit_text(text, **self._edit_kwargs)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("Failed to update Telegram progress message", exc_info=True)
                return False
            self._last_text = text
            return True

    async def refresh(self) -> bool:
        return await self._edit(include_metric=True)

    async def set_stage(
        self,
        *,
        symbol: str,
        label: str,
        progress: tuple[int, int] | None = None,
        show_elapsed: bool = True,
    ) -> bool:
        if self._closed:
            return False
        self._symbol = self._compact(symbol)
        self._label = self._compact(label)
        if progress is not None:
            self._metric_mode = "progress"
            self._progress = progress
        elif show_elapsed:
            self._metric_mode = "elapsed"
            self._progress = None
        else:
            self._metric_mode = "none"
            self._progress = None
        return await self._edit(include_metric=True)

    async def stop(self) -> None:
        ticker = self._ticker
        self._ticker = None
        if ticker is None:
            return
        ticker.cancel()
        try:
            await ticker
        except asyncio.CancelledError:
            pass

    async def delete(self, *, fallback_text: str = "") -> bool:
        await self.stop()
        if self._closed:
            return False
        self._closed = True
        try:
            await self.message.delete()
            return True
        except Exception:
            logger.debug("Failed to delete Telegram progress message", exc_info=True)

        fallback = self._compact(fallback_text)
        if not fallback:
            return False
        try:
            await self.message.edit_text(fallback, **self._edit_kwargs)
            self._last_text = fallback
            return True
        except Exception:
            logger.debug("Failed to retire Telegram progress message", exc_info=True)
            return False

    async def replace(self, text: str) -> bool:
        await self.stop()
        if self._closed:
            return False
        try:
            await self.message.edit_text(text, **self._edit_kwargs)
        except Exception:
            logger.debug("Failed to replace Telegram progress message", exc_info=True)
            return False
        self._last_text = text
        self._closed = True
        return True
