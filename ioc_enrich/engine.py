"""The engine: decides which lookups to make, runs them, and collects results.

- VirusTotal runs on ONE worker (the main thread) behind a rate limiter,
  because the free key allows only 4 requests per minute and 500 per day.
- All other sources run in a small thread pool, so they never wait for VT.
- Every fresh answer goes into the cache straight away, so an interrupted
  run can simply be started again and picks up where it stopped.
"""

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime, timezone
from threading import Event, Lock
from typing import Callable

from ioc_enrich.cache import Cache
from ioc_enrich.config import Keys
from ioc_enrich.lookup_plan import Lookup, LookupPlan
from ioc_enrich.http import RateLimited
from ioc_enrich.models import IOC, SourceResult
from ioc_enrich.ratelimit import RateLimiter
from ioc_enrich.sources import KEY_FIELD, LOOKUPS, vt

MAX_429_IN_A_ROW = 3
MAX_WAIT_SECONDS = 120        # a longer Retry-After means a daily limit: stop asking that source
OTHER_SOURCE_WORKERS = 4
RDAP_PER_MINUTE = 60          # rdap.org allows 10 requests per 10 seconds
INTERNETDB_PER_MINUTE = 60    # no published limit: stay polite with long IP lists


@dataclass
class RunOptions:
    """How to run. What to ask (no-vt, deep, keys) is decided by the lookup plan."""
    no_cache: bool = False
    vt_per_minute: int = 4
    vt_daily_limit: int = 500


@dataclass
class Cost:
    vt_calls: int
    vt_age_calls_max: int
    other_calls: int
    seconds: int

    def describe(self, n_iocs: int) -> str:
        """e.g. '12 IOCs → 9 VirusTotal lookups (+ up to 1 for domain age), about 2 min 15 s'"""
        lookups = f"{self.vt_calls} VirusTotal lookup{'s' if self.vt_calls != 1 else ''}"
        text = f"{n_iocs} IOC{'s' if n_iocs != 1 else ''} → {lookups}"
        if self.vt_age_calls_max:
            text += f" (+ up to {self.vt_age_calls_max} for domain age)"
        if self.seconds == 0:
            return text + ", no wait"
        minutes, seconds = divmod(self.seconds, 60)
        if minutes == 0:
            return text + f", about {seconds} s"
        return text + (f", about {minutes} min" if seconds == 0 else f", about {minutes} min {seconds} s")


class _QuotaExhausted(Exception):
    """The VT daily quota is used up; stop asking VT in this run."""


class _Stopped(Exception):
    """The run was stopped while this lookup was waiting its turn."""


def _key(source: str, keys: Keys) -> str | None:
    field = KEY_FIELD[source]
    return getattr(keys, field) if field else None


def estimate(plan: LookupPlan, cache: Cache, opts: RunOptions) -> Cost:
    """What a run would cost. No network, no keys."""
    def cached(lookup: Lookup):
        return None if opts.no_cache else cache.get(lookup.cache_name, lookup.cache_ioc)

    vt_calls = age_calls = other_calls = 0
    for item in plan.items:
        for lookup in item.lookups:
            if lookup.outcome != "ask":
                continue
            hit = cached(lookup)
            if lookup.source != "VT":
                other_calls += 0 if hit else 1
                continue
            if hit is None:
                vt_calls += 1
            # Exact follow-ups if VT's answer is cached, otherwise the possible ones.
            follow_ups = plan.follow_ups(lookup, hit) if hit else plan.possible_follow_ups(item.ioc)
            for follow_up in follow_ups:
                if cached(follow_up):
                    continue
                if follow_up.source == "VT-age":
                    age_calls += 1
                else:
                    vt_calls += 1
    seconds = (vt_calls + age_calls) * 60 // opts.vt_per_minute
    return Cost(vt_calls, age_calls, other_calls, seconds)


def run(plan: LookupPlan, keys: Keys, http, cache: Cache, opts: RunOptions,
        on_result: Callable[[IOC, SourceResult], None] = lambda ioc, result: None,
        today: Callable[[], date] = lambda: datetime.now(timezone.utc).date(),
        sleep=None, clock=time.monotonic, cancel: Event | None = None) -> dict[IOC, list[SourceResult]]:
    """Look up every planned IOC. Returns {ioc: [SourceResult, ...]}.

    on_result is called for every result as it arrives (possibly from a
    worker thread). On Ctrl-C (KeyboardInterrupt) the workers finish the
    request they are in, store it in the cache, and then the interrupt is
    re-raised. `sleep` is for tests; by default waits end early on Ctrl-C.

    cancel: set it (e.g. the web page's Stop) to finish the lookup in progress and
    start no new ones; run() then returns normally with the answers it has.
    """
    results: dict[IOC, list[SourceResult]] = {}
    lock = Lock()
    stop = cancel if cancel is not None else Event()   # set on Stop or Ctrl-C
    pause = sleep if sleep is not None else stop.wait
    given_up: dict[str, str] = {}                    # source -> reason, for this run

    def emit(ioc: IOC, result: SourceResult) -> None:
        with lock:
            results.setdefault(ioc, []).append(result)
        on_result(ioc, result)

    def from_cache(lookup: Lookup) -> SourceResult | None:
        return None if opts.no_cache else cache.get(lookup.cache_name, lookup.cache_ioc)

    def not_checked(source: str, reason: str) -> SourceResult:
        return SourceResult(source, "not_checked", today(), reason=reason)

    def store(lookup: Lookup, result: SourceResult) -> None:
        """Cache an answer. If the cache fails (e.g. "database is locked" while the
        web page and the CLI share it), keep the answer anyway: it just isn't cached."""
        try:
            cache.put(lookup.cache_name, lookup.cache_ioc, result)
        except Exception:
            pass

    # ---- other sources: thread pool ---------------------------------------
    rdap_limiter = RateLimiter(RDAP_PER_MINUTE, clock=clock, sleep=pause)
    internetdb_limiter = RateLimiter(INTERNETDB_PER_MINUTE, clock=clock, sleep=pause)

    def other_job(lookup: Lookup) -> None:
        source, ioc = lookup.source, lookup.ioc
        if stop.is_set():
            return
        with lock:
            reason = given_up.get(source)
        if reason:                               # this source hit its daily limit earlier
            emit(ioc, not_checked(source, reason))
            return
        for attempt in range(1, MAX_429_IN_A_ROW + 1):
            try:
                if source == "RDAP":
                    rdap_limiter.wait()
                elif source == "InternetDB":
                    internetdb_limiter.wait()
                if stop.is_set():
                    return
                result = LOOKUPS[source](ioc, _key(source, keys), http, today())
                break
            except RateLimited as limited:
                wait = limited.retry_after or 60
                if wait > MAX_WAIT_SECONDS or attempt == MAX_429_IN_A_ROW:
                    # Hours of Retry-After, or 429 after 429: a daily cap. Stop asking
                    # this source for the rest of the run instead of waiting per IOC.
                    reason = (f"rate limited (retry after {int(wait)} s)" if wait > MAX_WAIT_SECONDS
                              else "rate limited")
                    with lock:
                        given_up[source] = reason
                    result = not_checked(source, reason)
                    break
                pause(wait)
                if stop.is_set():
                    return
            except Exception as error:          # network error, bad JSON, ...
                result = not_checked(source, f"error: {type(error).__name__}")
                break
        store(lookup, result)
        emit(ioc, result)

    # ---- VirusTotal: one worker, rate limited -----------------------------
    vt_limiter = RateLimiter(opts.vt_per_minute, clock=clock, sleep=pause)
    vt_queue: deque[Lookup] = deque()
    quota_gone = False

    def vt_call(call: Callable[[], SourceResult]) -> SourceResult:
        """One VT request with 429 handling. Raises _QuotaExhausted."""
        in_a_row = 0
        while True:
            vt_limiter.wait()
            if stop.is_set():                # stopped while waiting for the rate limiter
                raise _Stopped()
            try:
                result = call()
                try:
                    cache.add_vt_call()
                except Exception:            # a failed counter must not lose the answer
                    pass
                return result
            except RateLimited as limited:
                in_a_row += 1
                wait = limited.retry_after or 60
                # Per-minute and daily 429s look the same; our own call
                # counter, repeated 429s and a very long Retry-After tell them apart.
                if (cache.vt_calls_today() >= opts.vt_daily_limit or in_a_row >= MAX_429_IN_A_ROW
                        or wait > MAX_WAIT_SECONDS):
                    raise _QuotaExhausted() from None
                pause(wait)

    def queue_follow_ups(lookup: Lookup, answer: SourceResult) -> None:
        """Ask the plan which follow-ups this VT answer makes due."""
        for follow_up in plan.follow_ups(lookup, answer):
            hit = from_cache(follow_up)
            if hit:
                emit(follow_up.ioc, hit)
            else:
                vt_queue.append(follow_up)

    def vt_call_for(lookup: Lookup) -> Callable[[], SourceResult]:
        key = keys.vt
        if lookup.source == "VT":
            return lambda: vt.lookup(lookup.ioc, key, http, today())
        if lookup.source == "VT-age":
            return lambda: vt.lookup_age(lookup.cache_ioc.value, key, http, today())
        return lambda: vt.lookup_related(lookup.ioc, lookup.relationship, key, http, today())

    def vt_job(lookup: Lookup) -> None:
        nonlocal quota_gone
        if quota_gone:
            emit(lookup.ioc, not_checked(lookup.source, "quota"))
            return
        try:
            result = vt_call(vt_call_for(lookup))
        except _Stopped:
            return
        except _QuotaExhausted:
            quota_gone = True
            emit(lookup.ioc, not_checked(lookup.source, "quota"))
            return
        except Exception as error:
            result = not_checked(lookup.source, f"error: {type(error).__name__}")
        store(lookup, result)
        emit(lookup.ioc, result)
        queue_follow_ups(lookup, result)

    # ---- carry out the plan's up-front lookups --------------------------------
    other_jobs = []
    for item in plan.items:
        for lookup in item.lookups:
            if lookup.outcome != "ask":           # skipped / not checked: decided by the plan
                emit(lookup.ioc, SourceResult(lookup.source, lookup.outcome, today(), reason=lookup.reason))
                continue
            hit = from_cache(lookup)
            if hit:
                emit(lookup.ioc, hit)
                queue_follow_ups(lookup, hit)
            elif lookup.source == "VT":
                vt_queue.append(lookup)
            else:
                other_jobs.append(lookup)

    pool = ThreadPoolExecutor(max_workers=OTHER_SOURCE_WORKERS)
    try:
        futures = [pool.submit(other_job, lookup) for lookup in other_jobs]
        while vt_queue and not stop.is_set():
            vt_job(vt_queue.popleft())
        for future in futures:
            future.result()       # re-raises KeyboardInterrupt (or any error) from a worker
    except BaseException:
        # Ctrl-C or an error: drop queued work, let running lookups finish and
        # reach the cache (waits end early via `stop`), then hand the error on.
        # Without this, queued lookups would keep running after run() gave up.
        stop.set()
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    pool.shutdown()
    return results
