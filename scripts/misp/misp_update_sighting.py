#!/usr/bin/env python3
import argparse
from datetime import datetime, timedelta
from pymisp import PyMISP, MISPEvent
import sqlite3
import logging
import sys
import os

# parse arguments
parser = argparse.ArgumentParser(description="Set to_ids flag for URLs in MISP.")
parser.add_argument("-m", "--misp-url", help="Base URL of the MISP instance", required=True)
parser.add_argument("-k", "--key", help="API key for the MISP instance", required=True)
parser.add_argument("-d", "--database", help="Path to URL evaluator database", required=True)
args = parser.parse_args()

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("MISP sighting")
logger.setLevel("INFO")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Connection to database
db_path = args.database
if not os.path.exists(db_path):
    logger.error(f"Database file {db_path} does not exist")
    exit()
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
logger.debug("Connected to database")

# get URLs that were seen yesterday
yesterday = datetime.today() - timedelta(days=1)
logger.debug(f"Yesterday date: {yesterday}")
cursor.execute("SELECT url FROM urls WHERE last_seen=? AND (classification='malicious' OR classification='miner')", (yesterday.date(),))
rows = cursor.fetchall()
conn.close()
print(rows)

if rows == []:
    logger.debug("No new changed URLs")
    exit()
else:
    logger.info(f"Found {len(rows)} URLs with changed status")

# logger.debug(rows)

# connect to MISP
misp_url = args.misp_url
api_key = args.key
verify_cert = False
misp = PyMISP(misp_url, api_key, verify_cert, debug=False)
logger.debug("Connected to MISP")

# set sighting for URLs that were lastly seen yesterday
for row in rows:
    sighting = {"value": row[0]}
    misp.add_sighting(sighting)
    
logger.info("Updated sighting of URLs in MISP")
