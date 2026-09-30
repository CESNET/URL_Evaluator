import regex
import hashlib
import logging
from collections import Counter, defaultdict
from urllib.parse import urlparse

try:
    from common import content_store
except Exception:  # pragma: no cover - optional dependency at import time
    content_store = None

LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger(__name__)

# Regex used to capture URLs found in shell commands
url_capture_regex = regex.compile(r"""
    (?<!                                  # Negative lookbehind (skip URLs after these flags):
        (?:--referer|-e)                  #   --referer or -e option
        (?:\s|'\s|"|\s'|\s")              #   followed by space or quoted space
    )
    (                                     # Capturing group: the URL itself
        https?://                         #   http:// or https://
        .*?                               #   non-greedy match of everything after
    )
    (?=                                   # Positive lookahead: stop match at
        \s | ; | \| | \\\\ | " | ' | $    #   whitespace, semicolon, pipe, backslash, quote, or end of string
    )
""", regex.VERBOSE)


# Regex used to capture shell commands in downloaded content
command_capture_regex = regex.compile(r"""
    (.*                            # Capture the entire line or command
        \b(?:curl|wget)\b          # Match 'curl' or 'wget' as whole words
        .*                         # Any characters (greedy) in between
        https?://[^\s]+            # A URL starting with http or https, up to the next space
        .*
    )
""", regex.VERBOSE)


def extract_urls(command: str):
    """
    Extract URLs from shell commands
    """
    return [url.strip() for url in url_capture_regex.findall(command)]


def extract_commands(content: str):
    """
    Extract shell commands from downloaded content
    """
    return "\n".join([cmd.strip() for cmd in command_capture_regex.findall(content)])


def is_valid(url: str):
    """
    Check whether a URL is valid
    """
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


def get_domain(url: str):
    """
    Get URL netloc (domain/IP and port)
    """
    try:
        return urlparse(url).netloc or None
    except ValueError as e:
        logger.warning(f"Skipping malformed URL: {url}")
        return None


def split_url_lines(text):
    """
    Split a raw multi-line / multi-URL user input into individual URL candidates.

    Accepts newline, comma and whitespace separated lists (the bulk-add popup
    pastes one URL per line, but analysts often paste space/comma separated
    lists too). Empty entries are dropped, order and duplicates are preserved
    (deduplication happens against the DB, not the input).
    """
    if not text:
        return []
    # normalise separators to newlines, then split
    normalised = text.replace(",", "\n").replace("\r", "\n")
    candidates = []
    for line in normalised.split("\n"):
        for token in line.split():
            token = token.strip()
            if token:
                candidates.append(token)
    return candidates


def add_urls_bulk(db, urls, source="Manual", seen_date=None, username=None):
    """
    Insert a batch of URLs into the DB (used by the web UI bulk-add popup).

    Each URL is validated with is_valid(); invalid entries are skipped and
    reported. URLs already present in the `urls` table are not duplicated –
    instead their `last_seen` is refreshed and occurrences incremented
    (consistent with the other collectors, e.g. honeynetasia2evaluator).

    Parameters:
        db        – an open SQLiteWrapper
        urls      – iterable of URL strings (already split/trimmed)
        source    – value written to url_source for newly inserted URLs
        seen_date – optional 'YYYY-MM-DD' string; defaults to today (UTC)
        username  – analyst username recorded in the observations table as the
                    "honeynet"/actor for manual entries (shows up in the GUI
                    Sources tab)

    Returns a dict with three lists: {
        "added":   [urls that were newly inserted],
        "in_db":   [urls that already existed (last_seen refreshed)],
        "invalid": [urls that failed validation and were skipped],
    }
    """
    from datetime import datetime, timezone
    date = seen_date or datetime.now(timezone.utc).strftime('%Y-%m-%d')
    result = {"added": [], "in_db": [], "invalid": []}
    for url in urls:
        if not is_valid(url):
            result["invalid"].append(url)
            continue
        existing = db.execute("SELECT 1 FROM urls WHERE url = ? LIMIT 1", (url,)).fetchone()
        if existing:
            db.execute(
                "UPDATE urls SET last_seen = ?, occurrences = occurrences + 1 WHERE url = ?",
                (date, url),
            )
            result["in_db"].append(url)
        else:
            db.execute(
                "INSERT INTO urls (url, first_seen, last_seen, domain) VALUES (?, ?, ?, ?)",
                (url, date, date, get_domain(url)),
            )
            db.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source))
            db.execute(
                """INSERT OR IGNORE INTO observations
                   (url, source, honeynet, session, observed_at)
                   VALUES (?, ?, ?, NULL, ?)""",
                (url, source, "Manual by " + username if username else source, date),
            )
            result["added"].append(url)
    return result


def process_new_session(db, config, session, idea_id, detect_time, source, source_url, honeynet=None):
    """
    Process a new session:
      1. Extract URLs from shell commands and store them into the DB
      2. Analyze the session and check for DDoS
         - check the number of occurrences of the same URL, if a threshold is exceeded the URL is classified as harmless
         - check the number of URLs from the same domain, if a threshold is exceeded all such URLs are deleted
    Returns a list of inserted URLs

    `source` identifies the ingest collector/pipeline (e.g. 'Warden', 'GEANT T-Pot'),
    while the optional `honeynet` identifies the physical honeynet node that captured
    the session (e.g. 'CESNET Hugo', 'CZ.NIC HaaS'). Each extracted URL is logged as
    an observation recording where (source/honeynet/session) and when it was seen.
    """

    inserted_urls = []
    session_hash = hashlib.md5(session.encode()).hexdigest()
    date = detect_time.split("T")[0]

    # Extract URLs from shell commands
    if not (extracted_urls := extract_urls(session)):
        return []
    url_domain = {url: get_domain(url) for url in extracted_urls}

    if source == "Warden (unknown node)":
        logger.info(f"URL(s) found in an event from unknown Warden node (ID: '{idea_id}')")

    # Store the session and contained URLs
    db.execute(
        """
        INSERT INTO sessions (session_hash, session, idea_id) VALUES (?, ?, ?)
        ON CONFLICT(session_hash) DO UPDATE SET idea_id = excluded.idea_id;
        """, (session_hash, session, idea_id)
    )
    for url, occurrences in Counter(extracted_urls).items():
        db.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, session_hash))
        db.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source))
        db.execute(
            "INSERT OR IGNORE INTO observations (url, source, honeynet, session, observed_at) VALUES (?, ?, ?, ?, ?)",
            (url, source, honeynet, session_hash, detect_time)
        )
        if source_url:
            db.execute("INSERT OR IGNORE INTO discovered_urls (url, src_url) VALUES (?, ?)", (url, source_url))
        db.execute(
            """
            INSERT INTO urls (url, first_seen, last_seen, domain) VALUES (?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                occurrences = occurrences + 1,
                last_seen = excluded.last_seen;
            """, (url, date, date, url_domain[url]))
        if db.cursor.lastrowid:
            inserted_urls.append(url)

        # Check the number of occurrences of the same URL
        if occurrences > config.ddos_threshold["same_url_single_session"]:
            logger.info(f"URL {url} was classified as harmless, reason: DDoS target")
            db.execute( "UPDATE urls SET evaluated='yes', classification='harmless', classification_reason='DDoS target' WHERE url=?", (url,))
            db.record_classification(url, "harmless", reason="DDoS target", actor="session-ddos")

    # Check the number of URLs from the same domain
    domain_map = defaultdict(list)
    for url, domain in url_domain.items():
        domain_map[domain].append(url)
    for domain, urls in domain_map.items():
        if len(urls) > config.ddos_threshold["same_domain_single_session"]:
            content_ids = set()
            if content_store is not None:
                try:
                    content_ids = {
                        cid for cid, _ in content_store.content_ids_for_urls(db, urls)
                    }
                except Exception as e:
                    logger.warning(f"Could not resolve content for session-flood URLs: {e}")
            if content_store is not None:
                content_store.delete_urls(db, urls)
            else:
                # Fallback (content_store unavailable): parameterised delete.
                placeholders = ",".join("?" for _ in urls)
                db.execute(f"DELETE FROM urls WHERE url IN ({placeholders})", list(urls))
            if content_store is not None and content_ids:
                try:
                    content_store.cleanup_orphan_content(db, candidates=content_ids)
                except Exception as e:
                    logger.warning(f"Orphan content cleanup failed (session flood): {e}")
            logger.info(f"Deleted {len(urls)} URLs from domain {domain} (session threshold exceeded)")
            logger.debug(f"Deleted URLs: {urls}")

    # Return a list of URLs that were actually inserted
    return inserted_urls
