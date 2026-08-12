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


def record_url_source(db, url, source, date=None, count=1):
    """
    Record that a URL was observed in a source (e.g. a honeynet feed).

    Tracks per-source observation statistics in the url_source table:
      - first_seen: date of the first observation of the URL in this source
      - last_seen: date of the most recent observation (updated to the latest)
      - occurrences: how many times the URL was observed in this source

    :param db: database wrapper with an execute() method
    :param url: observed URL
    :param source: name of the source (honeynet) the URL was observed in
    :param date: date of the observation (defaults to today, UTC)
    :param count: how many observations (occurrences) to add (default 1)
    """
    if date is None:
        from datetime import datetime, timezone
        date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    db.execute(
        """
        INSERT INTO url_source (url, source, first_seen, last_seen, occurrences) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(url, source) DO UPDATE SET
            occurrences = url_source.occurrences + excluded.occurrences,
            last_seen = MAX(url_source.last_seen, excluded.last_seen);
        """, (url, source, date, date, count))


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
        # Record/update per-source observation statistics (first/last seen, occurrences)
        record_url_source(db, url, source, date=date)
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
