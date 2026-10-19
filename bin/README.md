# bin/ README

## evaluator.py – evaluation pipeline (`evaluate_url`)

1. **Validity**: `is_valid()`. A URL that fails is classified `invalid`.
2. **Download and store content**: always done, even when a later check decides the result (`_fetch_and_store_content`).
3. **Domain flood check**: if the domain has more URLs than `ddos_threshold.same_domain_all_sessions`, its non-malicious URLs are deleted (`check_domain_threshold`).
4. **URLhaus blacklist**: a match is classified `malicious`.
5. **MalwareBazaar**: looks up the SHA-1 of the downloaded body. A match is classified `malicious`.
6. **VirusTotal URL lookup**.
7. **VirusTotal file-hash lookup** (`analyze_content`), only if the URL is still unclassified.

Before each URL, the main loop calls `_log_ha_usage_if_ha_stats_interval_minutes_reached()`. Every `ha_stats_interval_minutes` (default 10) it logs Hybrid Analysis usage: hashes checked, request rate and HTTP 429 hits. Then it resets the counters.

If the VT quota runs out, the URL is set to `evaluated=no, eval_later=yes` and retried after the daily quota resets.
