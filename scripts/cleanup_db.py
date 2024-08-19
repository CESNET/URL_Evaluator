import sqlite3

import argparse
import logging
import sys
import os
from datetime import date, timedelta

'''
Script removing records from database. Records of URLs that were not seen for 30 days are removed.
Run this script once a day.
Arguments:
    -d, --database: path to a database where URLs are stored
'''

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("cleanup_db")
logger.setLevel("DEBUG")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Parse arguments
parser = argparse.ArgumentParser(description="Script removig recods from database. Records of URLs that were not seen for 30 days are removed.")
parser.add_argument("--database", "-d", action="store", default="",
                    help="Path to a database where URLs are stored")
args = parser.parse_args()

# Check if database exists
if not os.path.isfile(args.database):
    logger.error("Invalid database file")
    sys.exit(1)

# Connect to database
conn = sqlite3.connect(args.database)
cursor = conn.cursor()

count = 0

# Remove records of inactive URLs older than 180 days
time_ago = date.today() - timedelta(days=180)
day = time_ago.strftime("%Y-%m-%d")

select = f"SELECT count(*) FROM urls WHERE last_seen<'{day}' AND status='inactive'"
count = conn.execute(select).fetchone()[0]
delete = f"DELETE FROM urls WHERE last_seen < '{day}' AND status='inactive'"
conn.execute(delete)
conn.commit()

# Remove records of invalid URLs older than 7 days
time_ago = date.today() - timedelta(days=7)
day = time_ago.strftime("%Y-%m-%d")
select = f"SELECT count(*) FROM urls WHERE last_seen<'{day}' AND classification='invalid'"
count += conn.execute(select).fetchone()[0]
delete = f"DELETE FROM urls WHERE last_seen < '{day}' AND classification='invalid'"
conn.execute(delete)
conn.commit()

logger.info(f"Removed {count} records of URLs")