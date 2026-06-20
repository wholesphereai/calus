"""
CALUS.learning.scheduler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Always-on background learning scheduler.

Starts automatically when CALUS is first used.
Runs learning cycles:
  - Every N new threats (default 10)
  - Daily at 02:00 UTC

Users never need to trigger this manually.
"""
from __future__ import annotations
import logging, threading, time
from datetime import datetime, date
from typing import Optional

log = logging.getLogger(__name__)

_instance: Optional["LearningScheduler"] = None
_lock = threading.Lock()


class LearningScheduler:
    """
    Singleton background scheduler.
    Started once via start() — then runs forever as a daemon thread.
    """

    def __init__(self, auto_every: int = 10, daily_hour: int = 2):
        self._auto_every  = auto_every
        self._daily_hour  = daily_hour
        self._running     = False
        self._thread: Optional[threading.Thread] = None
        self._last_daily: Optional[date] = None
        self._threats_since_cycle = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="CALUS-scheduler", daemon=True
        )
        self._thread.start()
        log.info("[CALUS:scheduler] started (auto_every=%d, daily_hour=%d)",
                 self._auto_every, self._daily_hour)

    def stop(self) -> None:
        self._running = False

    def notify_threat(self) -> None:
        """Called by interceptor every time a threat is detected."""
        with self._lock:
            self._threats_since_cycle += 1
            should_run = self._threats_since_cycle >= self._auto_every
            if should_run:
                self._threats_since_cycle = 0
        if should_run:
            threading.Thread(
                target=self._run_cycle, args=("auto",), daemon=True
            ).start()

    def _loop(self) -> None:
        while self._running:
            try:
                now = datetime.utcnow()
                if (now.hour == self._daily_hour
                        and now.date() != self._last_daily):
                    self._last_daily = now.date()
                    self._run_cycle("daily")
            except Exception as exc:
                log.debug("[CALUS:scheduler] loop error: %s", exc)
            time.sleep(60)  # check every minute

    def _run_cycle(self, reason: str) -> None:
        try:
            from calus.learning.engine import run_cycle_now
            log.info("[CALUS:scheduler] learning cycle triggered (%s)", reason)
            result = run_cycle_now()
            log.info(
                "[CALUS:scheduler] cycle done: new=%d pending=%d accepted=%d",
                result.get("new_patterns",0),
                result.get("pending",0),
                result.get("accepted",0),
            )
        except Exception as exc:
            log.warning("[CALUS:scheduler] cycle failed: %s", exc)


def get_scheduler() -> LearningScheduler:
    global _instance
    with _lock:
        if _instance is None:
            _instance = LearningScheduler()
        return _instance


def start() -> None:
    """Start the global scheduler. Called automatically on first observe()."""
    get_scheduler().start()


def notify_threat() -> None:
    """Notify scheduler a threat was found. Triggers auto-cycle if threshold hit."""
    get_scheduler().notify_threat()
