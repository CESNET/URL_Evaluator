#!/bin/env python3
# Script to archive incoming Warden messages into daily files.
# Each file conteins one IDEA message per line, files are named by date the
# messages were received.
#
# The current file is named YYYY-MM-DD.current. When date changes, this file is
# renamed to YYYY-MM-DD and the new .current file is created.

import signal
import sys
import os
import argparse
import logging
import sqlite3
import json
import hashlib
import time
import regex as re
from datetime import datetime
from datetime import timedelta
from warden_client import Client, Error, read_cfg
from collections import Counter


argparser = argparse.ArgumentParser(description="Warden source for URL evaluator -- receieves messages from Warden, finds suspicious URLs and saves them to URL evaluator database.")
argparser.add_argument('-w', '--warden_config', help='File with Warden configuration', required=True)
argparser.add_argument('-d', '--database', help='Path to URL evaluator database', required=True)
argparser.add_argument('-u', '--url_file', help='Path to directory where file with URLs that were discovered today should be stored', required=True)
argparser.add_argument('-l', '--log_file', help='File for logs', required=True)

# python3 /data/url_evaluator/warden_client/warden2evaluator.py -w /data/url_evaluator/warden_client/warden_client.cfg -u /data/url_evaluator/warden_client -d /data/url_evaluator/url.sqlite -l /data/url_evaluator/logs/warden2db.log

URLFORMAT = "(?<!(--referer|-e)(\s|\s\'|\s\"))(https?:\/\/.*?)(?=\s|;|\\||\\\\|\"|\')"

logger = None

# list of URLs discovered today
discovered_urls = []

# Additional config, may contain 'poll_time' and 'filter' (it could be settable by arguments, but it's not currently needed)
config = {'filter': {'cat': 'Intrusion.UserCompromise'}}

# variables for signal handling
def terminate_me(signum, frame):
    global running_flag
    running_flag = False

running_flag = True
signals = {
    signal.SIGTERM: terminate_me,
    signal.SIGINT: terminate_me,
}


def findURL(content, idea_id, detected_time, database, source_id):
    """
    Find URLs in commands an save them to database.

    :param commands: List of commands
    :param cursor: Cursor to database
    :param conn: Connection to database
    """

    global discovered_urls

    # hash of the command
    command_id = hashlib.md5(content.encode()).hexdigest()

    if 'curl' in content or 'wget' in content:
        urls_reg = re.findall(URLFORMAT, content) 
        if len(urls_reg) == 0:
            return
        conn = sqlite3.connect(database)
        cursor = conn.cursor()
        logger.debug(f"Found {urls_reg}") 
        found_urls = [x[2].strip() for x in urls_reg if x[2].strip()]
        agregated_urls = list(Counter(found_urls).items())

        for agr_url in agregated_urls:
            url = agr_url[0]
            if url == "":
                continue

            if url in discovered_urls:
                # add session to database
                cursor.execute("INSERT OR IGNORE INTO sessions (session_hash, session) VALUES (?, ?)", (command_id, content))
                cursor.execute("UPDATE OR IGNORE sessions SET idea_id = ? WHERE session_hash = ?", (idea_id, command_id))
                cursor.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, command_id))
                
                # add source to database
                cursor.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source_id))
                
                logger.debug("URL already discovered: %s, in content: %s", url, command_id)
                continue
            else:
                discovered_urls.append(url)

            logger.info("Found URL: %s", url)
            
            cursor.execute("INSERT OR IGNORE INTO urls (url, first_seen, url_occurrences, reported, evaluated) VALUES (?, ?, ?, ?, ?)", (url, detected_time, 0, "no", "no"))
            cursor.execute("UPDATE urls SET url_occurrences = url_occurrences + 1, last_seen = ?  WHERE url = ?", (detected_time, url))
            cursor.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source_id))

            
            # add session to database
            cursor.execute("INSERT OR IGNORE INTO sessions (session_hash, session) VALUES (?, ?)", (command_id, content))
            cursor.execute("UPDATE OR IGNORE sessions SET idea_id = ? WHERE session_hash = ?", (idea_id, command_id))

            cursor.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, command_id))

            conn.commit()

            # check if url could be DDoS target
            if agr_url[1] >= 10:
                logger.info(f"URL {url} evaluated as DDoS target")
                cursor.execute("UPDATE OR IGNORE urls SET evaluated = 'yes', classification = 'harmless', classification_reason = 'DDoS target' WHERE url = ?", (url,))
                conn.commit()
        conn.close()

# Copied from warden_filer, simplified and modified to write into a file rather than directory
def receiver(config, wclient, database):
    conf_filt = config.get("filter", {})
    filt = {}
    # Extract filter explicitly to be sure we have right param names for getEvents
    for s in ("cat", "nocat", "tag", "notag", "group", "nogroup"):
        filt[s] = conf_filt.get(s, None)

    # Setup signal handlers
    for (signum, handler) in signals.items():
        signal.signal(signum, handler)

    count = 0
    today = datetime.now().date()

    # get source_id
    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM sources WHERE source = ?", ("CESNET Hugo",))
    source_id = cursor.fetchone()
    if source_id is None:
        cursor.execute("INSERT INTO sources (name) VALUES (?)", ("CESNET Hugo",))
        conn.commit()
        cursor.execute("SELECT id FROM sources WHERE name = ?", ("CESNET Hugo",))
        source_id = cursor.fetchone()
    source_id = source_id[0] 
    conn.commit()
    conn.close() 

    while running_flag:
        events = wclient.getEvents(**filt)
        events_cnt = len(events)
        if events_cnt == 0:
            time.sleep(10)
            continue
        logger.debug("Received %d events", count)
        count += events_cnt

        if today != datetime.now().date():
            global discovered_urls
            discovered_urls = []
            today = datetime.now().date()

            # get source_id
            conn = sqlite3.connect(database)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM sources WHERE source = ?", ("CESNET Hugo",))
            source_id = cursor.fetchone()
            if source_id is None:
                cursor.execute("INSERT INTO sources (name) VALUES (?)", ("CESNET Hugo",))
                conn.commit()
                cursor.execute("SELECT id FROM sources WHERE name = ?", ("CESNET Hugo",))
                source_id = cursor.fetchone()
            source_id = source_id[0] 
            conn.commit()
            conn.close()    

        for event in events:

            if "Attach" not in event:
                continue

            for attach in event["Attach"]:
                if "Content" in attach:
                    detect_time = event.get("DetectTime")
                    detect_time = detect_time.split("T")[0]
                    content = attach["Content"]
                    if re.match("^\[(\'|\")(\r\n|\r|\n|.)*(\'|\")\]$", content):
                        content = content[2:-2]
                    logger.debug(f"Looking for URLs in content {content}")
                    findURL(content, event.get("ID"), detect_time, database, source_id)

    conn.close()


def main():
    # Parse arguments
    args = argparser.parse_args()

    # Set logger
    global logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    logging.basicConfig(filename=args.log_file, filemode="a", format=LOGFORMAT, level=logging.INFO)
    logger = logging.getLogger("warden2evaluator")

    logger.info("Starting warden2evaluator")

    # Create Warden client
    wclient = Client(**read_cfg(args.warden_config))
    
    # Run receiver
    receiver(config, wclient, args.database)


if __name__ == "__main__":
    main()
