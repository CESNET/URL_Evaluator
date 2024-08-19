#!/bin/env python3
# Script to archive incoming Warden messages into daily files.
# Each file conteins one IDEA message per line, files are named by date the
# messages were received.
#
# The current file is named YYYY-MM-DD.current. When date changes, this file is
# renamed to YYYY-MM-DD and the new .current file is created.

import sys
import os
import argparse
import logging
import sqlite3
import json
import hashlib
import regex as re
from datetime import datetime
from datetime import timedelta
from warden_client import Client, Error, read_cfg

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("warden2db")
logger.setLevel("DEBUG")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

argparser = argparse.ArgumentParser(description="Warden source for URL evaluator -- receieves messages from Warden, finds suspicious URLs and saves them to URL evaluator database.")
argparser.add_argument('-w', '--warden_config', help='File with Warden configuration', required=True)
argparser.add_argument('-d', '--database', help='Path to URL evaluator database', required=True)
argparser.add_argument('-u', '--url_file', help='Path to directory where file with URLs that were discovered today should be stored', required=True)

URLFORMAT = "(?<!(--referer|-e)(\s|\s\'|\s\"))(https?:\/\/.*?)(?=\s|;|\\||\\\\|\"|\')"

# list of URLs discovered today
discovered_urls = []
discovered_urls_file = ""

# Additional config, may contain 'poll_time' and 'filter' (it could be settable by arguments, but it's not currently needed)
config = {'filter': {'cat': 'Intrusion.UserCompromise'}}

def load_discovered_urls(path):
    global urls
    global discovered_urls_file

    # Get today's date and name of file with discovered URLs
    today = datetime.now()
    date = today.strftime("%Y-%m-%d")   
    file_name = date + "-urls.txt"
    discovered_urls_file = os.path.join(path, file_name)

    # if file from yesterday exists, delete it
    yesterday = today - timedelta(days = 1)
    date = yesterday.strftime("%Y-%m-%d")
    file_name = date + "-urls.txt"
    yesterday_file = os.path.join(path, file_name)
    if os.path.isfile(yesterday_file):
        os.remove(yesterday_file)

    # load URLs from today's file
    if os.path.isfile(discovered_urls_file):
        with open(discovered_urls_file, 'r') as f:
            urls = f.readlines()
    else:
        open(discovered_urls_file, 'w').close()


def findURL(content, idea_id, detected_time, cursor, conn, source_id):
    """
    Find URLs in commands an save them to database.

    :param commands: List of commands
    :param cursor: Cursor to database
    :param conn: Connection to database
    """

    # hash of the command
    command_id = hashlib.md5(content.encode()).hexdigest()

    if 'curl' in content or 'wget' in content:
        urls_reg = re.findall(URLFORMAT, content) 
        if len(urls_reg) == 0:
            return
        for urls in urls_reg:
            for url in urls:
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
                    with open(discovered_urls_file, 'a') as f:
                        f.write(url + "\n")

                logger.info("Found URL: %s", url)
                
                cursor.execute("INSERT OR IGNORE INTO urls (url, first_seen, url_occurrences, reported, evaluated) VALUES (?, ?, ?, ?, ?)", (url, detected_time, 0, "no", "no"))
                cursor.execute("UPDATE urls SET url_occurrences = url_occurrences + 1, last_seen = ?  WHERE url = ?", (detected_time, url))
                cursor.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source_id))

                
                # add session to database
                cursor.execute("INSERT OR IGNORE INTO sessions (session_hash, session) VALUES (?, ?)", (command_id, content))
                cursor.execute("UPDATE OR IGNORE sessions SET idea_id = ? WHERE session_hash = ?", (idea_id, command_id))

                cursor.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, command_id))

                conn.commit()

# Copied from warden_filer, simplified and modified to write into a file rather than directory
def receiver(config, wclient, database):
    conf_filt = config.get("filter", {})
    filt = {}
    # Extract filter explicitly to be sure we have right param names for getEvents
    for s in ("cat", "nocat", "tag", "notag", "group", "nogroup"):
        filt[s] = conf_filt.get(s, None)


    count = 0

    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    
    # get source_id
    cursor.execute("SELECT id FROM sources WHERE source = ?", ("CESNET Hugo",))
    source_id = cursor.fetchone()
    if source_id is None:
        cursor.execute("INSERT INTO sources (name) VALUES (?)", ("CESNET Hugo",))
        conn.commit()
        cursor.execute("SELECT id FROM sources WHERE name = ?", ("CESNET Hugo",))
        source_id = cursor.fetchone()
    source_id = source_id[0]

    while True:
        events = wclient.getEvents(**filt)
        events_cnt = len(events)
        if events_cnt == 0:
            break
        count += events_cnt

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
                    findURL(content, event.get("ID"), detect_time, cursor, conn, source_id)

    conn.close()

    logger.info("Received %d events", count)


                    


def main():
    # Parse arguments
    args = argparser.parse_args()

    # Load URLs discovered today
    load_discovered_urls(args.url_file)
    
    # Create Warden client
    wclient = Client(**read_cfg(args.warden_config))
    
    # Run receiver
    receiver(config, wclient, args.database)


if __name__ == "__main__":
    main()