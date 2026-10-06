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

# Per-run counters shared by the worker threads (reset by activity_scanner()).
run_stats = Counter()
run_stats_lock = threading.Lock()


def _count(key, n=1):
    with run_stats_lock:
        run_stats[key] += n


def _record_daily_fetch(db, url, response, body, fetched_at):
    """
    Daily re-verification: deduplicate the returned payload, write a
    download_observation row and let the helper flag whether the content
    changed since the previous fetch.
    """
    if content_store is None:
        logger.warning("Content store module not available, skipping daily fetch record for %s", url)
        return

    content_id = None
    if body is None:
        # No body to store (e.g. error response), but the download observation
        # (status code, headers, ...) is still recorded below.
        logger.warning(f"Thread: no body for {url}, status code is {getattr(response, 'status_code', None)} – recording observation without content")
    else:
        content_dir = getattr(config, "content_dir", None)
        if not content_dir:
            logger.warning(
                f"Thread: 'content_dir' is not configured, skipping content storage "
                f"for {url} ({len(body)} bytes will not be persisted)"
            )
        else:
            try:
                # create content dir if not exists
                content_store.ensure_content_dir(content_dir)
            except OSError as e:
                logger.warning(
                    f"Thread: content directory {content_dir} is not usable "
                    f"(check permissions/mount), skipping content storage for {url}: {e}"
                )
            else:
                info = content_store.get_or_create_content(db, content_dir, body, url=url)
                if info is None:
                    logger.warning(
                        f"Thread: content for {url} ({len(body)} bytes) could not be "
                        f"stored on disk – download observation will be recorded "
                        f"without content (marked as unavailable)"
                    )
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
        )
    except Exception as e:
        logger.warning(f"Thread: could not record daily fetch for {url}: {e}")


def thread_func(thread_id, urls):
    """Worker process: re-poll each URL, record a download observation (content
    dedup + change detection) and update its active/inactive status."""
    with SQLiteWrapper(config.db_path) as db:
        for url, current_status, last_active in urls:
            if not is_valid(url):
                continue

            # Send a HTTP request to check whether the URL is active
            fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            body = None
            resp = None
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
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                logger.debug(f"Thread {thread_id}: Connection error or timeout for {url}, marking as inactive")
                new_status = "inactive"

            # Daily content-change detection / history (best effort)
            _record_daily_fetch(db, url, resp, body, fetched_at)

            # Update DB record
            logger.debug(f'Thread {thread_id}: Updating DB record for {url}')
            last_active = datetime.now(timezone.utc).date() if new_status == 'active' else last_active
            db.execute("UPDATE urls SET status = ?, last_active = ? WHERE url = ?", (new_status, last_active, url))
            _count("urls_updated")
            _count(f"urls_{new_status}")
            if new_status != current_status:
                db.execute("UPDATE urls SET status_changed = 'yes' WHERE url = ?", (url,))
                _count("urls_status_changed")
    logger.info(f'Thread {thread_id}: Finished')


def activity_scanner():
    logger.info("Job started")
    started = time.monotonic()
    with run_stats_lock:
        run_stats.clear()
    if hybrid_analysis is not None:
        hybrid_analysis.reset_request_stats()

    with SQLiteWrapper(config.db_path) as db:
        urls = db.execute("SELECT url, status, last_active FROM urls").fetchall()
    logger.info(f"Loaded {len(urls)} URLs, processing...")

    # Chunking: spawn one worker thread per chunk of max 1000 URLs, so URLs are re-polled in parallel.
    url_limit = 1000
    thread_id = 1
    threads = []
    for start_idx in range(0, len(urls), url_limit):
        chunk = urls[start_idx:start_idx + url_limit]
        logger.debug(f'Thread {thread_id}: first = {start_idx}, last = {len(chunk)}')
        thread = threading.Thread(target=thread_func, args=(thread_id, chunk))
        thread_id += 1
        thread.start()
        threads.append(thread)

    # Wait for every worker, then report the whole run.
    for thread in threads:
        thread.join()
    _log_run_summary(len(urls), time.monotonic() - started)


def _log_run_summary(urls_loaded, elapsed):
    """Log what the finished run updated and how hard it used the Hybrid Analysis API."""
    with run_stats_lock:
        st = dict(run_stats)
    minutes = max(elapsed / 60, 1 / 60)
    logger.info(
        f"Job finished in {elapsed / 60:.1f} min: {st.get('urls_updated', 0)}/{urls_loaded} URLs updated "
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
    logger = logging.getLogger("activity_status.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    # Set HTTP proxy
    proxies = {}
    if config.http_proxy:
        proxies = {
            "http": config.http_proxy,
            "https": config.http_proxy
        }

    logger.info("Started")
    if args.now:
        activity_scanner()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(activity_scanner, "cron", **config.scheduler["activity_scanner"])
    scheduler.start()

    logger.info("Stopped")
