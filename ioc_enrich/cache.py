"""SQLite cache of lookup results (and the VT daily call counter).

The cache is also the "progress file": every answer is stored as soon as it
arrives, so an interrupted run can simply be started again.
"""

import json
import sqlite3
import threading
import time
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from ioc_enrich.models import IOC, SourceResult

DEFAULT_CACHE_FILE = Path.home() / ".cache" / "ioc-enrich" / "cache.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    source TEXT, ioc_type TEXT, value TEXT, fetched_at REAL, payload TEXT,
    PRIMARY KEY (source, ioc_type, value));
CREATE TABLE IF NOT EXISTS vt_calls (day TEXT PRIMARY KEY, count INTEGER);
"""


class Cache:
    def __init__(self, path: Path = DEFAULT_CACHE_FILE, ttl_days: int = 7, now=time.time):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_days * 86400
        self.now = now
        # One connection shared by the worker threads, protected by a lock.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.lock = threading.Lock()

    def close(self) -> None:
        self.db.close()

    def get(self, source: str, ioc: IOC) -> SourceResult | None:
        """The stored result, or None if missing or older than the TTL."""
        with self.lock:
            row = self.db.execute(
                "SELECT fetched_at, payload FROM results WHERE source=? AND ioc_type=? AND value=?",
                (source, ioc.type, ioc.value)).fetchone()
        if row is None or self.now() - row[0] > self.ttl_seconds:
            return None
        data = json.loads(row[1])
        data["fetched_on"] = date.fromisoformat(data["fetched_on"])
        data["cached"] = True
        return SourceResult(**data)

    def put(self, source: str, ioc: IOC, result: SourceResult) -> None:
        """Store a result. 'not_checked' is never stored: there is no answer to keep."""
        if result.status == "not_checked":
            return
        data = asdict(result)
        data["fetched_on"] = result.fetched_on.isoformat()
        data["cached"] = False
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?)",
                            (source, ioc.type, ioc.value, self.now(), json.dumps(data)))
            self.db.commit()

    def _today(self) -> str:
        return datetime.fromtimestamp(self.now(), timezone.utc).date().isoformat()

    def vt_calls_today(self) -> int:
        """VT requests made so far today (UTC). Used to spot the daily quota."""
        with self.lock:
            row = self.db.execute("SELECT count FROM vt_calls WHERE day=?", (self._today(),)).fetchone()
        return row[0] if row else 0

    def add_vt_call(self) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO vt_calls VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET count = count + 1",
                (self._today(),))
            self.db.commit()
