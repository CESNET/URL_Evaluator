import regex
import hashlib
import logging
from collections import Counter, defaultdict
from urllib.parse import urlparse

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


def _origin_source_of(db, url):
    """
    Resolve the (source, source_detail) of a URL's first observation, used to
    derive the original honeynet of a URL extracted from that URL's content.
    Dict/tuple-row tolerant. Returns (None, None) when not observed yet.
    """
    origin = db.execute(
        "SELECT source, source_detail FROM url_source WHERE url = ? ORDER BY observed_at, rowid LIMIT 1",
        (url,)).fetchone()
    if not origin:
        return None, None
    if isinstance(origin, dict):
        return origin.get("source"), origin.get("source_detail")
    return origin[0], origin[1]


def record_url_source(db, url, source, date=None, count=1, source_detail=None, origin_url=None,
                      observed_at=None, idea_id=None, session_hash=None):
    """
    Record that a URL was observed in a source (e.g. a honeynet feed).

    Tracks per-source observation statistics in the url_source table:
      - first_seen: date of the first observation of the URL in this source
      - last_seen: date of the most recent observation (updated to the latest)
      - occurrences: how many times the URL was observed in this source
      - observed_at: when the URL was first observed (kept at the earliest value)
      - source_detail / origin_url / idea_id / session_hash: provenance metadata

    For URLs extracted from a script hosted on another URL (``origin_url``), the
    original source (``origin_source`` / ``origin_source_detail``) is resolved
    from the origin URL's own first observation, so the original honeynet can be
    derived.

    :param db: database wrapper with an execute() method
    :param url: observed URL
    :param source: name of the source (honeynet) the URL was observed in
    :param date: date of the observation (defaults to today, UTC)
    :param count: how many observations (occurrences) to add (default 1)
    :param source_detail: detail of the source (sensor/node name)
    :param origin_url: URL from which this URL was extracted (if any)
    :param observed_at: when the URL was observed (defaults to now, UTC)
    :param idea_id: IDEA event ID
    :param session_hash: hash of the session the URL was observed in
    """
    from datetime import datetime, timezone
    if date is None:
        date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    if observed_at is None:
        observed_at = datetime.now(timezone.utc).isoformat()

    # Resolve the original source of a URL extracted from another URL's content,
    # so the original honeynet can be derived. Uses the origin URL's first observation.
    origin_source = origin_source_detail = None
    if origin_url:
        origin_source, origin_source_detail = _origin_source_of(db, origin_url)

    # Schema-adaptive column list: the production url_source carries cumulative
    # stats columns (first_seen/last_seen/occurrences), but a minimal schema may not.
    def _col_name(row):
        # PRAGMA table_info row: (cid, name, ...) as tuple, or {'name': ...} with a dict row factory
        if isinstance(row, dict):
            return row.get("name")
        return row[1]

    existing = {_col_name(row) for row in db.execute("PRAGMA table_info(url_source)").fetchall()}

    columns = ["url", "source"]
    values = [url, source]
    if "first_seen" in existing:
        columns += ["first_seen", "last_seen", "occurrences"]
        values += [date, date, count]
    columns += ["source_detail", "origin_url", "origin_source", "origin_source_detail",
                "observed_at", "idea_id", "session_hash"]
    values += [source_detail, origin_url, origin_source, origin_source_detail,
               observed_at, idea_id, session_hash]

    updates = []
    if "occurrences" in existing:
        updates.append("occurrences = url_source.occurrences + excluded.occurrences")
    if "last_seen" in existing:
        updates.append("last_seen = MAX(url_source.last_seen, excluded.last_seen)")
    updates.append("observed_at = MIN(url_source.observed_at, excluded.observed_at)")

    placeholders = ", ".join("?" * len(columns))
    db.execute(
        f"""
        INSERT INTO url_source ({", ".join(columns)})
        VALUES ({placeholders})
        ON CONFLICT(url, source) DO UPDATE SET
            {", ".join(updates)};
        """,
        values)


def record_discovered_url(db, url, src_url, discovered_at=None):
    """
    Record that a URL was found in the content of another URL.

    Stores the link in discovered_urls, caching the original source of the
    ``src_url`` (the URL hosting the script this URL was extracted from), so the
    original honeynet can be derived.

    :param db: database wrapper with an execute() method
    :param url: the discovered (extracted) URL
    :param src_url: the URL in whose content ``url`` was found
    :param discovered_at: when the URL was discovered (defaults to now, UTC)
    """
    from datetime import datetime, timezone
    if discovered_at is None:
        discovered_at = datetime.now(timezone.utc).isoformat()

    # Cache the original source of the src_url (its first observation).
    origin_source, origin_source_detail = _origin_source_of(db, src_url)

    db.execute(
        """
        INSERT INTO discovered_urls (url, src_url, discovered_at, origin_source, origin_source_detail)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(url, src_url) DO NOTHING;
        """,
        (url, src_url, discovered_at, origin_source, origin_source_detail))


def process_new_session(db, config, session, idea_id, detect_time, source, source_url):
    """
    Process a new session:
      1. Extract URLs from shell commands and store them into the DB
      2. Analyze the session and check for DDoS
         - check the number of occurrences of the same URL, if a threshold is exceeded the URL is classified as harmless
         - check the number of URLs from the same domain, if a threshold is exceeded all such URLs are deleted
    Returns a list of inserted URLs
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
        # Record/update per-source observation statistics (first/last seen, occurrences, provenance)
        record_url_source(
            db, url, source,
            date=date,
            source_detail=source_url,
            origin_url=source_url,
            observed_at=detect_time,
            idea_id=idea_id,
            session_hash=session_hash)
        if source_url:
            record_discovered_url(db, url, source_url, discovered_at=detect_time)
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

    # Check the number of URLs from the same domain
    domain_map = defaultdict(list)
    for url, domain in url_domain.items():
        domain_map[domain].append(url)
    for domain, urls in domain_map.items():
        if len(urls) > config.ddos_threshold["same_domain_single_session"]:
            db.execute(f"DELETE FROM urls WHERE url IN {tuple(urls)}")
            logger.info(f"Deleted {len(urls)} URLs from domain {domain} (session threshold exceeded)")
            logger.debug(f"Deleted URLs: {urls}")

    # Return a list of URLs that were actually inserted
    return inserted_urls
