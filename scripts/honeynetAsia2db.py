#!/usr/bin/env python3
""" This script downloads honeypot URL data from Honeynet.Asia, replaces 'hxxp://' with 'http://' and saves data to database. """
import argparse
import sqlite3
import os
import sys
import requests
from datetime import datetime
import logging
import time

import validators

def execute_sql(cursor, sql, data):
    """ Execute SQL command and commit changes """
    added = False
    while not added:
        try:
            cursor.execute(sql, data)
            cursor.connection.commit()
            added = True
        except sqlite3.OperationalError:
            logger.debug("Database locked, waiting 2 seconds")
            time.sleep(2)

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("HoneynetAsia2db")
logger.setLevel("DEBUG")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Parse arguments
parser = argparse.ArgumentParser(description="Download data from the Honeynet.Asia Project website and save it to the database.")
parser.add_argument("--database", "-d", action="store", default="",
                    help="Path to a database to store URLs")
args = parser.parse_args()

# Get current date
data_date = datetime.date(datetime.utcnow())

# Check if database exists
if not os.path.isfile(args.database):
    logger.error("Invalid database file")
    sys.exit(1)

# Download data from the Honeynet.Asia
url = "https://feeds.honeynet.asia/url/latest-url-unique.csv"
data = requests.get(url, timeout=20)
if data.status_code != 200:
    logger.error(f"Failed to download data from Honeynet.Asia. Status code: {data.status_code}")
    sys.exit(1)

# Connect to database
conn = sqlite3.connect(args.database)
cursor = conn.cursor()
conn.execute("PRAGMA foreign_keys = ON;")
conn.commit()
sql = "SELECT id FROM sources WHERE source = ?"
cursor.execute(sql, ("HoneyNet.Asia",))
source_id = cursor.fetchone()
if not source_id:
    execute_sql(cursor, "INSERT INTO sources (source) VALUES (?)", ("HoneyNet.Asia",))
    # cursor.execute("INSERT INTO sources (source) VALUES (?)", ("HoneyNet.Asia",))
    # conn.commit()
    cursor.execute(sql, ("HoneyNet.Asia",))
    source_id = cursor.fetchone()
source_id = source_id[0]


# parse content into list of URLs
cnt_new = 0
cnt_known = 0

for line in data.content.splitlines():
    line = line.decode().strip()
    if line == "":
        continue
    url = line.replace("hxxp://", "http://")
    if not validators.url(url):
        logger.error(f"Invalid URL (skipped): {url}")
        continue
    if url == "":
        continue
    cursor.execute("SELECT * FROM urls WHERE url = ?", (url,))
    if not cursor.fetchall():
        # add new URL
        execute_sql(cursor, "INSERT INTO urls (url, first_seen, last_seen, url_occurrences, reported, evaluated) VALUES (?, ?, ?, ?, ?, ?)", (url, data_date, data_date, 1, "no", "no"))
        # cursor.execute("INSERT INTO urls (url, first_seen, last_seen, url_occurrences, reported, evaluated) VALUES (?, ?, ?, ?, ?, ?)", (url, data_date, data_date, 1, "no", "no"))
        # conn.commit()
        cnt_new += 1
    else: 
        # update last seen and occurrences
        execute_sql(cursor, "UPDATE urls SET last_seen = ?, url_occurrences = url_occurrences + 1 WHERE url = ?", (data_date, url))
        # cursor.execute("UPDATE urls SET last_seen = ?, url_occurrences = url_occurrences + 1 WHERE url = ?", (data_date, url))
        # conn.commit()
        cnt_known += 1

    # add source
    execute_sql(cursor, "INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (url, source_id))
    # sql = "INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)"
    # cursor.execute(sql, (url, source_id))
    # conn.commit()


# Close database connection
conn.close()

logger.info(f"Data successfully downloaded, {cnt_new} new URLs added to database, {cnt_known} already known URLs updated.")
