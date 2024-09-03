import argparse
import json
import logging
import os
import sqlite3
import sys
import requests
from datetime import date

'''
URLhaus sample python3 code for submitting malware URLs the bulk API
See https://urlhaus.abuse.ch/api/
    - token (required)
    - anonymous (optional, default: 0)
    - url (required)
    - threat (required, supported values: malware_download)
    - tags (optional)
'''

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("send2urlhaus")
logger.setLevel("DEBUG")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Parse arguments
parser = argparse.ArgumentParser(description="Script adding malicious URLs to URLhaus.")
parser.add_argument("--database", "-d", action="store", default="",
                    help="Path to a database where URLs are stored")
parser.add_argument("--key", "-k", action="store", required=True,
                    help="API key for URLhaus")
args = parser.parse_args()

# Check if database exists
if not os.path.isfile(args.database):
    logger.error("Invalid database file")
    sys.exit(1)

# Connect to database
conn = sqlite3.connect(args.database)
cursor = conn.cursor()
today = date.today()
day = today.strftime("%Y-%m-%d")
select = f"SELECT url FROM urls WHERE classification='malicious' AND status='active'"
urls = conn.execute(select).fetchall()
logger.info(f"Found {len(urls)} malicious URLs")

if len(urls) == 0:
    sys.exit(0)

# Load blacklist
downloaded_bl = requests.get("https://urlhaus.abuse.ch/downloads/text/")
blacklist = downloaded_bl.content.decode("utf-8").splitlines()
blacklist = [item for item in blacklist if not item.startswith("#")]

urlhaus = 'https://urlhaus.abuse.ch/api/'

jsonData = {
    'token': args.key,
    'anonymous': '0',
    'submission': []
}

headers = {
    "Content-Type": "application/json"
}

cnt = 0
cnt_submissions = 0
for url in urls:
    if url[0] in blacklist:
        continue
    cnt += 1
    jsonData = {
        'token': args.key,
        'anonymous': '0',
        'submission': [{
            'url': url[0],
            'threat': 'malware_download'
        }]
    }
    r = requests.post(urlhaus, json=jsonData, timeout=15, headers=headers)
    logger.info(f"URL '{url[0]}' was sent to URLhaus. Response code: {r.status_code}")
    if r.status_code == 200:
        cnt_submissions += 1
    logger.debug(f"Response: {r.content}")

logger.info(f"Sent {cnt_submissions} URLs to URLhaus out of {cnt} URLs")