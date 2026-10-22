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
   - The hash already has a report: the verdict decides (`malicious` → `malicious`, `whitelisted` → `harmless`, other verdicts leave it `unclassified`). Reason `Hybrid Analysis check`.
   - The hash was never analysed (HTTP 404): the content is submitted (`submit_content`, `submitted_by = 'evaluator'`, environment `ha_environment_id`). The URL stays `unclassified` for now.

### Scheduled fetches of evaluator's submissions (`fetch_job`)

A `BackgroundScheduler` job (`common/ha_fetch_scheduler.FetchJob(config, by_evaluator=True)`) runs every 60 s (`POLL_SECONDS`) and fetches the reports of evaluator's own submissions 10, 20 and 30 min after the submission, the same way activity_scanner does for the web UI ones. With no report after 30 min, the daily activity_scanner run takes over.

**URL classification by a found report** (`hybrid_analysis.finish_submissions` → `classify_urls`, the same for every submission and every process that finds the report): the verdict classifies every evaluated URL that served this content and is `unclassified` at that moment (history actor `hybrid-analysis`). Its `unclassified` source URLs become malicious too (actor `hybrid-analysis-backprop`). An already classified URL is never changed. A URL not evaluated yet is left to evaluator, which uses the same report (step 8).

Before each URL, the main loop calls `_log_ha_usage_if_ha_stats_interval_minutes_reached()`. Every `ha_stats_interval_minutes` (default 10) it logs Hybrid Analysis usage: hashes checked, request rate and HTTP 429 hits. Then it resets the counters.

If the VT quota runs out, the URL is set to `evaluated=no, eval_later=yes` and retried after the daily quota resets.

## activity_scanner.py – scan pipeline (`activity_scanner` → `_run` → `thread_func`)

Runs on the cron schedule `scheduler.activity_scanner`. It runs immediately on start when `--now` is passed or the previous run was interrupted. Only one run can be in progress at a time (`run_lock`).

1. **Start or resume a run**: if the last row in `activity_scanner_runs` has no `finished_at`, the run is resumed. Otherwise a new run is created.
2. **Load URLs**: all URLs in `urls` that are not yet in `activity_scanner_progress` for this run.
3. **Split into threads**: one worker thread per 1000 URLs.
4. **Per URL** (`thread_func`):
   1. **Validity**: `is_valid()`. Invalid URLs are marked processed and skipped.
   2. **Fetch**: GET with a 10 s timeout. An OK response means `active`. An error status, connection error or timeout means `inactive`.
   3. **Store content** (`_record_daily_fetch`): the body is deduplicated into `content_dir`, followed by a Hybrid Analysis SHA-256 check (`check_content_outcome`). A `download_observation` row is always written, with or without a body.
   4. **Update `urls`**: `status`, `last_scanned`, and `last_active` (only when active). Sets `status_changed = 'yes'` when the status flips.
   5. **Mark processed**: the URL is added to `activity_scanner_progress`.
5. **Finish**: once all threads have joined, the run gets `finished_at` and its progress rows are deleted. If the run was stopped with URLs left, it stays open and is resumed on the next start.
   Then the reports of samples submitted from the web UI that the scheduled fetches did not find are fetched (`fetch_unfinished_results`). Samples whose hash was already queried in this run are skipped.
6. **Summary** (`_log_run_summary`): logs URLs updated, active, inactive and status-changed, plus Hybrid Analysis usage. It warns on HTTP 429 or when the peak reaches 200 requests/min.

### Scheduled fetches of submitted samples (`ha_fetch_scheduler.FetchJob`)

This covers the web UI submissions only (evaluator fetches its own): `FetchJob(config, by_evaluator=False)`. A found report classifies only the URLs that are `unclassified` at that moment (see the evaluator section). When an analyst submits a sample from the web UI (Sandbox tab), `submit_content` sets `sandbox_submissions.next_fetch_at` to 10 minutes after the submission. Every 60 s (`POLL_SECONDS`), independently of the daily run, `fetch_due_results` sends GET /overview/{sha256} for every pending submission whose `next_fetch_at` has passed:

- **Report found**: the submission is marked `done` (with its verdict), the lookup is stored in `content.sandbox_info` and the unclassified URLs serving the sample are classified by the verdict.
- **Not ready (404), failed, raised or skipped (paused after 429)**: `fetch_attempts` is incremented and `next_fetch_at` moves to the next time of the schedule (20, then 30 min after the submission, `ha_fetch_schedule_minutes`).
- **After the last scheduled fetch**: `next_fetch_at` becomes NULL and the next daily run fetches the report (step 5). The daily run fetches evaluator's submissions too.

On SIGINT, SIGTERM or SIGABRT, `stop_event` is set: each worker finishes its current URL and stops, and the remaining URLs are left for the resumed run.
