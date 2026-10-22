#Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Scheduled fetches of Hybrid Analysis reports of submitted samples.

``hybrid_analysis.submit_content`` stores the first fetch time of a
submission in ``sandbox_submissions.next_fetch_at`` (10 min after the
submission). ``FetchJob`` runs every ``POLL_SECONDS`` in an APScheduler
thread and sends GET /overview/{sha256} for every submission whose fetch time
has come (``fetch_due_results``), i.e. 10, 20 and 30 min after the submission
(``ha_fetch_schedule_minutes``). When the last of them finds no report, the
schedule ends (``next_fetch_at`` = NULL) and the next regular
activity_scanner run fetches it (``fetch_unfinished_results``).

Both evaluator (its own submissions) and activity_scanner (web UI
submissions) use it. A found report classifies the URLs serving the sample
that are unclassified at that moment, already classified URLs are never
changed (``hybrid_analysis.finish_submissions``).
"""

import logging
import threading
from collections import Counter
from datetime import datetime, timezone

from common import hybrid_analysis as ha
from common.db import SQLiteWrapper

logger = logging.getLogger(__name__)

# How often the scheduled fetches are checked for being due.
POLL_SECONDS = 60


def _waiting_statuses_sql():
    """Placeholders ("?, ?, ...") for ha.WAITING_SUBMISSION_STATUSES in an SQL IN clause."""
    return ", ".join("?" * len(ha.WAITING_SUBMISSION_STATUSES))


def _fetch_result(db, config, submission_id, content_id, sha256):
    """
    Send GET /overview/{sha256} for a waiting submission and store the answer
    (content.sandbox_info, submission status, classification of unclassified
    URLs). Returns the lookup outcome ('checked' / 'failed' / 'skipped') and
    whether the report exists.
    """
    if content_id is not None:
        result, outcome = ha.check_content_outcome(db, config, content_id, sha256, force=True)
    else:
        # The content row was purged -- only the submission can be updated.
        result = ha.lookup_sha256(config, sha256)
        outcome = "skipped" if result is None else (
            "checked" if result["http_status"] in ha.ANSWER_STATUSES else "failed")
        if outcome == "checked" and result.get("tested"):
            ha.finish_submissions(db, sha256, result)
    found = bool(outcome == "checked" and result and result.get("tested"))
    if not found and outcome != "skipped":
        db.execute("UPDATE sandbox_submissions SET last_fetch_at = ? WHERE id = ?",
                   ((result or {}).get("checked_at"), submission_id))
    return outcome, found


def fetch_due_results(db, config, by_evaluator=None, now=None):
    """
    Fetch the report of every submission whose scheduled fetch time
    (``next_fetch_at``: 10, 20, 30 min after the submission) has come.
    `by_evaluator` True / False limits it to the submissions made / not made
    by evaluator (each process fetches its own), None fetches all.

    A fetch that finds the report marks the submission done. Otherwise the
    next scheduled time is set, or -- after the last one -- the schedule ends
    (``next_fetch_at`` = NULL) and fetch_unfinished_results() of the next
    regular activity_scanner run takes over. A fetch that could not be sent
    (API disabled / paused after HTTP 429) or failed still uses up its time
    slot, so a submission gets at most one GET per scheduled time.

    Returns a Counter: 'found', 'not_ready', 'failed', 'skipped', 'schedule_ended'.
    Never raises.
    """
    stats = Counter()
    if not ha.is_enabled(config):
        return stats
    now = now or datetime.now(timezone.utc)
    submitter, params = "", ()
    if by_evaluator is not None:
        submitter = " AND submitted_by IS ?" if by_evaluator else " AND submitted_by IS NOT ?"
        params = (ha.EVALUATOR_SUBMITTER,)
    try:
        due = db.execute(
            "SELECT id, content_id, sha256, submitted_at, fetch_attempts FROM sandbox_submissions "
            "WHERE sandbox_name = ? AND next_fetch_at IS NOT NULL AND next_fetch_at <= ? "
            f"AND status IN ({_waiting_statuses_sql()}){submitter} ORDER BY next_fetch_at",
            (ha.SANDBOX_NAME, now.isoformat(timespec="seconds"), *ha.WAITING_SUBMISSION_STATUSES, *params),
        ).fetchall()
    except Exception as e:
        logger.warning(f"Cannot read scheduled Hybrid Analysis fetches (apply DB migrations via install/migrate.sh): {e}")
        return stats

    for submission_id, content_id, sha256, submitted_at, attempts in due:
        attempts += 1
        try:
            outcome, found = _fetch_result(db, config, submission_id, content_id, sha256)
        except Exception as e:
            outcome, found = "failed", False
            logger.warning(f"Scheduled Hybrid Analysis fetch of submission {submission_id} failed: {e}")
        try:
            if found:
                stats["found"] += 1
                db.execute("UPDATE sandbox_submissions SET fetch_attempts = ? WHERE id = ?", (attempts, submission_id))
                logger.info(f"Hybrid Analysis: report of submitted {sha256} fetched (scheduled fetch {attempts})")
                continue
            stats["not_ready" if outcome == "checked" else outcome] += 1
            next_at = ha.scheduled_fetch_at(config, submitted_at, now)
            db.execute("UPDATE sandbox_submissions SET fetch_attempts = ?, next_fetch_at = ? WHERE id = ?",
                       (attempts, next_at, submission_id))
            if next_at is None:
                stats["schedule_ended"] += 1
                logger.info(f"Hybrid Analysis: no report of submitted {sha256} after {attempts} scheduled "
                            f"fetch(es), the next activity_scanner run fetches it")
            else:
                logger.info(f"Hybrid Analysis: report of submitted {sha256} not ready ({outcome}), next fetch at {next_at}")
        except Exception as e:
            logger.warning(f"Could not store the fetch schedule of submission {submission_id}: {e}")
    return stats


def fetch_unfinished_results(db, config, checked_since=None):
    """
    Fetch the report of every submission still waiting after its scheduled
    fetches ended (called once per regular activity_scanner run).

    Submissions whose content was already looked up at or after
    `checked_since` (ISO timestamp, e.g. the start of the run) are skipped --
    the run has just queried their hash.

    Returns a Counter like fetch_due_results(). Never raises.
    """
    stats = Counter()
    if not ha.is_enabled(config):
        return stats
    try:
        waiting = db.execute(
            "SELECT s.id, s.content_id, s.sha256, c.sandbox_info FROM sandbox_submissions s "
            "LEFT JOIN content c ON c.id = s.content_id "
            "WHERE s.sandbox_name = ? AND s.next_fetch_at IS NULL "
            f"AND s.status IN ({_waiting_statuses_sql()})",
            (ha.SANDBOX_NAME, *ha.WAITING_SUBMISSION_STATUSES),
        ).fetchall()
    except Exception as e:
        logger.warning(f"Cannot read waiting Hybrid Analysis submissions (apply DB migrations via install/migrate.sh): {e}")
        return stats

    for submission_id, content_id, sha256, sandbox_info in waiting:
        lookup = ha.get_lookup(sandbox_info) or {}
        if checked_since and (lookup.get("checked_at") or "") >= checked_since:
            continue
        try:
            outcome, found = _fetch_result(db, config, submission_id, content_id, sha256)
            stats["found" if found else ("not_ready" if outcome == "checked" else outcome)] += 1
        except Exception as e:
            stats["failed"] += 1
            logger.warning(f"Hybrid Analysis fetch of submission {submission_id} failed: {e}")
    return stats


class FetchJob:
    """
    APScheduler job running fetch_due_results() every POLL_SECONDS with its
    own DB connection (it runs in a scheduler thread).

    `by_evaluator`: which submissions this process fetches (see fetch_due_results).
    """

    def __init__(self, config, by_evaluator=None):
        self.config = config
        self.by_evaluator = by_evaluator
        # A poll still waiting on Hybrid Analysis makes the next tick skip,
        # so a due submission is not fetched (and its API quota spent) twice.
        self._lock = threading.Lock()

    def schedule(self, scheduler):
        """Register the job in an APScheduler `scheduler`."""
        scheduler.add_job(self.run, "interval", seconds=POLL_SECONDS)

    def run(self):
        """One poll: fetch the due reports and log a summary. Never raises."""
        if not self._lock.acquire(blocking=False):
            return
        try:
            with SQLiteWrapper(self.config.db_path) as db:
                st = fetch_due_results(db, self.config, self.by_evaluator)
            if st:
                logger.info(
                    f"Hybrid Analysis scheduled fetches of submitted samples: {st.get('found', 0)} report(s) fetched, "
                    f"{st.get('not_ready', 0)} not ready yet, {st.get('failed', 0)} failed, "
                    f"{st.get('skipped', 0)} skipped (disabled / paused after 429), "
                    f"{st.get('schedule_ended', 0)} left to the next daily activity_scanner run"
                )
        except Exception as e:
            logger.warning(f"Scheduled Hybrid Analysis fetches failed: {e}")
        finally:
            self._lock.release()
