#!/usr/bin/env python3

import argparse
import logging
import threading
import sys
import os
import signal
import time
import requests
from collections import Counter
from datetime import datetime, timezone
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import is_valid
try:
    from common import content_store
except Exception:
    content_store = None
try:
    from common import hybrid_analysis
except Exception:
    hybrid_analysis = None

logger = logging.getLogger("activity_status.py")

# Module state, set by init() (called from __main__ and by tests)
config = None
proxies = {}


def init(cfg):
    """Set the module state (config, HTTP proxy) from `cfg`. Called by __main__ and by tests."""
    global config, proxies
    config = cfg

    # Set HTTP proxy
    proxies = {}
    if config.http_proxy:
        proxies = {
            "http": config.http_proxy,
            "https": config.http_proxy
        }


# Per-run counters shared by the worker threads (reset by activity_scanner()).
run_stats = Counter()
run_stats_lock = threading.Lock()

# Set by the signal handler: workers stop after the URL they are processing.
stop_event = threading.Event()
# Only one run at a time (a resumed run may overlap the scheduled one).
run_lock = threading.Lock()


def _count(key, n=1):
    with run_stats_lock:
        run_stats[key] += n


def _record_daily_fetch(db, url, response, body, fetched_at, fetch_error=None):
    """
    Daily re-verification: deduplicate the returned payload, write a
    download_observation row and let the helper flag whether the content
    changed since the previous fetch. `fetch_error` is the reason the request
    itself failed (no response); other no-content reasons are derived here.
    """
    if content_store is None:
        logger.warning("Content store module not available, skipping daily fetch record for %s", url)
        return

    content_id = None
    if body is None:
        # No body to store (e.g. error response), but the download observation
        # (status code, headers, ...) is still recorded below.
        logger.warning(f"Thread: no body for {url}, status code is {getattr(response, 'status_code', None)} – recording observation without content")
        if fetch_error is None:
            if response is None:
                fetch_error = "connection_error"
            elif not response.ok:
                fetch_error = "http_error"
            else:
                fetch_error = "body_unreadable"
    else:
        content_dir = getattr(config, "content_dir", None)
        if not content_dir:
            logger.warning(
                f"Thread: 'content_dir' is not configured, skipping content storage "
                f"for {url} ({len(body)} bytes will not be persisted)"
            )
            fetch_error = "storage_disabled"
        else:
            try:
                # create content dir if not exists
                content_store.ensure_content_dir(content_dir)
            except OSError as e:
                logger.warning(
                    f"Thread: content directory {content_dir} is not usable "
                    f"(check permissions/mount), skipping content storage for {url}: {e}"
                )
                fetch_error = "storage_failed"
            else:
                info = content_store.get_or_create_content(db, content_dir, body, url=url)
                if info is None:
                    logger.warning(
                        f"Thread: content for {url} ({len(body)} bytes) could not be "
                        f"stored on disk – download observation will be recorded "
                        f"without content (marked as unavailable)"
                    )
                    fetch_error = "storage_failed"
                else:
                    content_id = info.get("id")
                    _count("content_stored")
                    # Has this payload already been analysed on Hybrid Analysis?
                    if hybrid_analysis is not None:
                        result, outcome = hybrid_analysis.check_content_outcome(
                            db, config, content_id, info.get("sha256"))
                        _count(f"ha_{outcome}")
                        if result and result.get("tested") and outcome in ("checked", "cached"):
                            _count("ha_tested")
    try:
        content_store.record_download_observation(
            db,
            url,
            content_id=content_id,
            fetched_at=fetched_at,
            source_ip=content_store.resolve_source_ip(url),
            status_code=getattr(response, "status_code", None),
            response_headers=dict(getattr(response, "headers", {}) or {}),
            fetch_error=fetch_error,
        )
    except Exception as e:
        logger.warning(f"Thread: could not record daily fetch for {url}: {e}")


def thread_func(thread_id, run_id, urls):
    """Worker process: re-poll each URL, record a download observation (content
    dedup + change detection) and update its active/inactive status. Every
    finished URL is stored in activity_scanner_progress, so a run interrupted
    by a stop signal is resumed from where it ended."""
    with SQLiteWrapper(config.db_path) as db:
        for url, current_status, last_active in urls:
            if stop_event.is_set():
                logger.info(f"Thread {thread_id}: Stop requested, leaving remaining URLs for the resumed run")
                break
            if not is_valid(url):
                _mark_processed(db, run_id, url)
                continue

            # Send a HTTP request to check whether the URL is active
            fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            body = None
            resp = None
            fetch_error = None
            try:
                with requests.get(url, stream=True, proxies=proxies, timeout=10) as r:
                    resp = r
                    if r.ok:
                        new_status = "active"
                        try:
                            body = r.content
                        except Exception:
                            logger.warning(f"Thread {thread_id}: Could not read response body for {url}, skipping content-change detection")
                            body = None
                    else:
                        new_status = "inactive"
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                logger.debug(f"Thread {thread_id}: Connection error or timeout for {url}, marking as inactive")
                new_status = "inactive"
                fetch_error = content_store.fetch_error_from_exception(e) if content_store else None

            # Daily content-change detection / history (best effort)
            _record_daily_fetch(db, url, resp, body, fetched_at, fetch_error)

            # Update DB record
            logger.debug(f'Thread {thread_id}: Updating DB record for {url}')
            last_active = datetime.now(timezone.utc).date() if new_status == 'active' else last_active
            db.execute("UPDATE urls SET status = ?, last_active = ?, last_scanned = ? WHERE url = ?",
                       (new_status, last_active, fetched_at, url))
            _count("urls_updated")
            _count(f"urls_{new_status}")
            if new_status != current_status:
                db.execute("UPDATE urls SET status_changed = 'yes' WHERE url = ?", (url,))
                _count("urls_status_changed")
            _mark_processed(db, run_id, url)
    logger.info(f'Thread {thread_id}: Finished')


def _mark_processed(db, run_id, url):
    """Remember that `url` is done in run `run_id`."""
    db.execute("INSERT OR IGNORE INTO activity_scanner_progress (run_id, url) VALUES (?, ?)", (run_id, url))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def unfinished_run(db):
    """Return (id, started_at) of the last run when it did not finish, else None."""
    return db.execute(
        "SELECT id, started_at FROM activity_scanner_runs WHERE finished_at IS NULL "
        "AND id = (SELECT MAX(id) FROM activity_scanner_runs)"
    ).fetchone()


def activity_scanner():
    if not run_lock.acquire(blocking=False):
        logger.warning("Job skipped: the previous run is still in progress")
        return
    try:
        _run()
    finally:
        run_lock.release()


def _run():
    if stop_event.is_set():
        return
    logger.info("Job started")
    started = time.monotonic()
    with run_stats_lock:
        run_stats.clear()
    if hybrid_analysis is not None:
        hybrid_analysis.reset_request_stats()

    with SQLiteWrapper(config.db_path) as db:
        # Resume the last run when it was interrupted, otherwise start a new one.
        previous = unfinished_run(db)
        if previous:
            run_id = previous[0]
            done = db.execute("SELECT COUNT(*) FROM activity_scanner_progress WHERE run_id = ?", (run_id,)).fetchone()[0]
            logger.info(f"Resuming interrupted run {run_id} started at {previous[1]} ({done} URLs already processed)")
        else:
            run_id = db.execute("INSERT INTO activity_scanner_runs (started_at) VALUES (?)", (_now(),)).lastrowid
        urls = db.execute(
            "SELECT url, status, last_active FROM urls WHERE NOT EXISTS "
            "(SELECT 1 FROM activity_scanner_progress p WHERE p.run_id = ? AND p.url = urls.url)",
            (run_id,)
        ).fetchall()
    logger.info(f"Run {run_id}: loaded {len(urls)} URLs, processing...")

    # Chunking: spawn one worker thread per chunk of max 1000 URLs, so URLs are re-polled in parallel.
    url_limit = 1000
    thread_id = 1
    threads = []
    for start_idx in range(0, len(urls), url_limit):
        chunk = urls[start_idx:start_idx + url_limit]
        logger.debug(f'Thread {thread_id}: first = {start_idx}, last = {len(chunk)}')
        thread = threading.Thread(target=thread_func, args=(thread_id, run_id, chunk))
        thread_id += 1
        thread.start()
        threads.append(thread)

    # Wait for every worker, then report the whole run.
    for thread in threads:
        thread.join()

    interrupted = False
    with SQLiteWrapper(config.db_path) as db:
        remaining = db.execute(
            "SELECT COUNT(*) FROM urls WHERE NOT EXISTS "
            "(SELECT 1 FROM activity_scanner_progress p WHERE p.run_id = ? AND p.url = urls.url)",
            (run_id,)
        ).fetchone()[0]
        if stop_event.is_set() and remaining:
            interrupted = True
            logger.info(f"Run {run_id} interrupted, {remaining} URLs left -- they are processed on the next start")
        else:
            db.execute("UPDATE activity_scanner_runs SET finished_at = ? WHERE id = ?", (_now(), run_id))
            db.execute("DELETE FROM activity_scanner_progress WHERE run_id = ?", (run_id,))
    _log_run_summary(len(urls), time.monotonic() - started, interrupted)


def _log_run_summary(urls_loaded, elapsed, interrupted=False):
    """Log what the finished run updated and how hard it used the Hybrid Analysis API."""
    with run_stats_lock:
        st = dict(run_stats)
    minutes = max(elapsed / 60, 1 / 60)
    logger.info(
        f"Job {'interrupted' if interrupted else 'finished'} after {elapsed / 60:.1f} min: {st.get('urls_updated', 0)}/{urls_loaded} URLs updated "
        f"(active {st.get('urls_active', 0)}, inactive {st.get('urls_inactive', 0)}, "
        f"status changed {st.get('urls_status_changed', 0)}), content stored for {st.get('content_stored', 0)} URLs"
    )
    if hybrid_analysis is None:
        return
    ha = hybrid_analysis.request_stats()
    logger.info(
        f"Hybrid Analysis: {st.get('ha_checked', 0) + st.get('ha_cached', 0)} URLs with hash successfully checked "
        f"({st.get('ha_checked', 0)} queried now, {st.get('ha_cached', 0)} from recent stored result), "
        f"{st.get('ha_tested', 0)} already analysed by HA, {st.get('ha_failed', 0)} failed, "
        f"{st.get('ha_skipped', 0)} skipped (disabled / paused after 429)"
    )
    logger.info(
        f"Hybrid Analysis API usage: {ha['requests']} GET requests, avg {ha['requests'] / minutes:.1f}/min, "
        f"peak {ha['peak_per_minute']} in any 60 s window (quota 200/min), "
        f"HTTP statuses {ha['by_status']}, last Api-Limits {ha['api_limits']}"
    )
    rate_limited = ha["by_status"].get(429, 0)
    if rate_limited:
        logger.warning(f"Hybrid Analysis: HTTP 429 (rate limit) received {rate_limited}x during this run")
    elif ha["peak_per_minute"] >= 200:
        logger.warning("Hybrid Analysis: peak request rate reached the 200/min quota")


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    # Workers finish the URL they are processing, the rest is resumed on the next start.
    stop_event.set()
    scheduler.shutdown(wait=True)


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="Actively scans URLs from the DB and checks whether they are currently active (accessible)")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config (also sets the HTTP proxy)
    logger.debug(f"Loading config from {args.config}")
    try:
        init(Config(args.config))
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(activity_scanner, "cron", **config.scheduler["activity_scanner"])

    # Register signal handlers (the handler needs the scheduler)
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    logger.info("Started")
    try:
        with SQLiteWrapper(config.db_path) as db:
            interrupted = unfinished_run(db)
    except Exception as e:
        logger.fatal(f"Cannot read activity_scanner run state (apply DB migrations via install/migrate.sh): {e}")
        sys.exit(1)
    if interrupted:
        logger.info(f"Run {interrupted[0]} started at {interrupted[1]} was interrupted, resuming it now")
    # One-off job without a trigger runs right after the scheduler starts.
    if interrupted or args.now:
        scheduler.add_job(activity_scanner)
    scheduler.start()

    logger.info("Stopped")
