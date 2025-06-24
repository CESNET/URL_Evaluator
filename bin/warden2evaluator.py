#!/usr/bin/env python3

import signal
import sys
import os
import argparse
import logging
import hashlib
import time
import regex as re
from collections import Counter
from datetime import datetime, timezone
from warden_client import Client, Error, read_cfg

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import extract_urls


def get_source(node_name):
    """
    Returns the first source where the pattern matches node_name, or None if no match is found
    """
    for source, pattern in warden_sources.items():
        if pattern.search(node_name):
            return source
    return None


def process_attachment(db, commands, idea_id, detected_time, source):
    """
    Extract URLs from shell commands executed during a honeypot session and save them to database
    """

    global discovered_today
    session_hash = hashlib.md5(commands.encode()).hexdigest()

    if not any(tool in commands for tool in ("curl", "wget")):
        return

    db.execute(
        """
        INSERT INTO sessions (session_hash, session, idea_id) VALUES (?, ?, ?)
        ON CONFLICT(session_hash) DO UPDATE SET idea_id = excluded.idea_id;
        """, (session_hash, commands, idea_id)
    )

    for url, cnt in Counter(extract_urls(commands)).items():
        db.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, session_hash))

        if url in discovered_today:
            logger.debug(f"URL already discovered: {url}")
            continue
        discovered_today.add(url)

        logger.info(f"Discovered new URL: {url}")
        db.execute(
            """
            INSERT INTO urls (url, first_seen, last_seen, src) VALUES (?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                occurrences = occurrences + 1,
                last_seen = excluded.last_seen;
            """, (url, detected_time, detected_time, source),)

        if cnt >= 10:
            db.execute("UPDATE urls SET evaluated = 'yes', classification = 'harmless', classification_reason = 'DDoS target' WHERE url = ?", (url,))

def receiver():
    """
    Receive messages from Warden
    """

    today = datetime.now(timezone.utc).date()
    while running_flag:
        if not (events := wclient.getEvents(**wfilter)):
            time.sleep(10)
            continue
        logger.debug("Received %d events", len(events))

        if today != datetime.now(timezone.utc).date():
            global discovered_today
            discovered_today = set()
            today = datetime.now(timezone.utc).date()

        with SQLiteWrapper(config.db_path) as db:
            for event in events:
                if not (source := get_source(event.get("Node", [{}])[-1].get("Name", ""))):
                    continue
                for attachment in event.get("Attach", []):
                    if "Content" in attachment:
                        detect_time = event.get("DetectTime")
                        detect_time = detect_time.split("T")[0]
                        content = attachment["Content"]
                        if re.match("^\[(\'|\")(\r\n|\r|\n|.)*(\'|\")\]$", content):
                            content = content[2:-2]  # Unwrap
                        logger.debug(f"Looking for new URLs in '{content}'")

                        # Search for new URLs
                        process_attachment(db, content, event.get("ID"), detect_time, source)


def sigint_handler(signum, frame):
    global running_flag
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    running_flag = False


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Receives messages from Warden, extracts suspicious URLs and stores them into Evaluator DB")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("warden2evaluator.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Load list of allowed node names
    warden_sources = dict()
    for source, pattern in config.warden_sources.items():
        warden_sources[source] = re.compile(pattern)

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    # Run Warden client
    logger.info("Started")
    running_flag = True
    discovered_today = set()
    wfilter = {'cat': 'Intrusion.UserCompromise'}
    wclient = Client(**read_cfg(config.warden_config))
    receiver()
    logger.info("Stopped")
