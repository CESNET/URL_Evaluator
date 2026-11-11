# bin/ README

## evaluator.py – evaluation pipeline (`evaluate_url`)

1. **Validity**: `is_valid()`. A URL that fails is classified `invalid`.
2. **Download and store content**: always done, even when a later check decides the result (`_fetch_and_store_content`). New content is classified by Magika and its SHA-256 is looked up on Hybrid Analysis right away. These results alone do not change the URL classification (see step 8).
3. **Domain flood check**: if the domain has more URLs than `ddos_threshold.same_domain_all_sessions`, its non-malicious URLs are deleted (`check_domain_threshold`).
4. **URLhaus blacklist**: a match is classified `malicious`.
5. **MalwareBazaar**: looks up the SHA-1 of the downloaded body. A match is classified `malicious`.
6. **VirusTotal URL lookup**.
7. **VirusTotal file-hash lookup** (`analyze_content`), only if the URL is still unclassified.
8. **Hybrid Analysis** (`_submit_unclassified_content`), only if the URL is still unclassified (not when it was postponed by the VT quota) and Magika classified its content as `executable` or `script`:
   - The hash already has a report: only the verdict `malicious` decides (→ `malicious`, reason `Hybrid Analysis check`, threat label from `vx_family`). Every other verdict (`whitelisted`, `suspicious`, `no specific threat`, …) leaves the URL `unclassified` and the content is not submitted. Hybrid Analysis never classifies a URL `harmless`.
   - The hash was never analysed (HTTP 404): the content is submitted (`submit_content`, `submitted_by = 'evaluator'`, environment `ha_environment_id`). The URL stays `unclassified` for now.

### Scheduled fetches of evaluator's submissions (`fetch_job`)

A `BackgroundScheduler` job (`common/ha_fetch_scheduler.FetchJob(config, by_evaluator=True)`) runs every 60 s (`POLL_SECONDS`) and fetches the reports of evaluator's own submissions 10, 20 and 30 min after the submission, the same way activity_scanner does for the web UI ones. With no report after 30 min, the daily activity_scanner run takes over.

**When a report is found** (`hybrid_analysis.finish_submissions` → `classify_urls`)

This is the continuation of step 8 for a submitted file. Evaluator finishes the URL right after the submission (`evaluated = yes`, `unclassified`) and moves on, because the analysis on Hybrid Analysis takes minutes. The report is found later in one of two ways:

- a scheduled fetch of `fetch_job` (10, 20 or 30 min after the submission) gets it, or
- evaluator meets the same file again at another URL, and its lookup in step 2 gets the report.

From that moment the URL is classified as follows.

A report belongs to a file (its SHA-256), not to a URL. The same file can be served by several URLs, so the report is applied to all of them. Only a `malicious` verdict does anything; any other verdict changes nothing.

Example: the file served by `http://b.test/x86` gets a `malicious` report.

| URL | Its state when the report is found | Result |
|---|---|---|
| `b.test/x86` (served the file) | `unclassified` | → `malicious`, reason `Hybrid Analysis check` (history actor `hybrid-analysis`) |
| | already classified by another check | unchanged (HA only fills gaps) |
| | not evaluated yet | unchanged, evaluator uses the same report later (step 8) |

When the report makes `b.test/x86` malicious, the URLs whose content downloads it (e.g. a script with `wget http://b.test/x86`) become malicious too, the same back-propagation as in evaluator (`mark_source_urls_malicious`, history actor `hybrid-analysis-backprop`).

These rules are the same whoever submitted the file (evaluator or the web UI) and whichever process found the report.

Before each URL, the main loop calls `_log_ha_usage_if_ha_stats_interval_minutes_reached()`. Every `ha_stats_interval_minutes` (default 10) it logs Hybrid Analysis usage: hashes checked, request rate and HTTP 429 hits. Then it resets the counters.

If the VT quota runs out, the URL is set to `evaluated=no, eval_later=yes` and retried after the daily quota resets.

## activity_scanner.py – scan pipeline (`activity_scanner` → `_run` → `thread_func`)

Runs on the cron schedule `scheduler.activity_scanner`. It runs immediately on start when `--now` is passed or the previous run was interrupted. Only one run can be in progress at a time (`run_lock`).

1. **Start or resume a run**: if the last row in `activity_scanner_runs` has no `finished_at`, the run is resumed. Otherwise a new run is created.
2. **Load URLs**: all URLs in `urls` that are not yet in `activity_scanner_progress` for this run.
3. **Split into threads**: one worker thread per 1000 URLs (`URLS_PER_THREAD`).
4. **Per URL** (`thread_func`):
   1. **Validity**: `is_valid()`. Invalid URLs are marked processed and skipped.
   2. **Fetch**: GET with a 10 s timeout. An OK response means `active`; a body larger than `max_file_size` (by `Content-Length`) is not downloaded (`fetch_error = 'oversized'`). An error status or any request error (connection error, timeout, too many redirects, …) means `inactive`.
   3. **Store content** (`_record_daily_fetch`): the body is deduplicated into `content_dir` and a `download_observation` row is written (always, with or without a body). Then the SHA-256 is looked up on Hybrid Analysis (`check_content_outcome`); a found report of a waiting submission classifies the URL (see the evaluator section).
   4. **Update `urls`**: `status`, `last_scanned`, and `last_active` (only when active). `status_changed` is `'yes'` when the status flipped in this scan, otherwise `'no'`.
   5. **Mark processed**: the URL is added to `activity_scanner_progress`. An unexpected error while scanning a URL is logged and counted (`urls_failed`); the URL is marked processed too, the thread goes on and the next daily run retries it.
5. **Finish**: once all threads have joined, the run gets `finished_at` and its progress rows are deleted. If the run was stopped with URLs left, it stays open and is resumed on the next start.
   Then the reports of samples submitted from the web UI that the scheduled fetches did not find are fetched (`fetch_unfinished_results`). Samples whose hash was already queried in this run (also before an interruption) are skipped.
6. **Summary** (`_log_run_summary`): logs URLs updated, active, inactive, status-changed and failed, plus Hybrid Analysis usage. It warns on HTTP 429 or when the peak reaches 200 requests/min.

### Scheduled fetches of submitted samples (`ha_fetch_scheduler.FetchJob`)

This covers the web UI submissions only (evaluator fetches its own): `FetchJob(config, by_evaluator=False)`. A found report classifies only the URLs that are `unclassified` at that moment (see the evaluator section). When an analyst submits a sample from the web UI (Sandbox tab), `submit_content` sets `sandbox_submissions.next_fetch_at` to 10 minutes after the submission. Every 60 s (`POLL_SECONDS`), independently of the daily run, `fetch_due_results` sends GET /overview/{sha256} for every pending submission whose `next_fetch_at` has passed:

- **Report found**: the submission is marked `done` (with its verdict), the lookup is stored in `content.sandbox_info` and the unclassified URLs serving the sample are classified by the verdict.
- **Not ready (404), failed, raised or skipped (paused after 429)**: `fetch_attempts` is incremented and `next_fetch_at` moves to the next time of the schedule (20, then 30 min after the submission, `ha_fetch_schedule_minutes`).
- **After the last scheduled fetch**: `next_fetch_at` becomes NULL and the next daily run fetches the report (step 5). The daily run fetches evaluator's submissions too.

On SIGINT, SIGTERM or SIGABRT, `stop_event` is set: each worker finishes its current URL and stops, and the remaining URLs are left for the resumed run.
