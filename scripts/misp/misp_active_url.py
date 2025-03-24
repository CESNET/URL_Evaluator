#!/usr/bin/env python3
import argparse
from pymisp import ExpandedPyMISP, MISPEvent
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
logger = logging.getLogger("MISP active URL")
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

# get URLs whose status (active/inactive) has changed
SQL_FILTER = "status_changed = 'yes' and (classification = 'malicious' or classification = 'miner')"
cursor.execute("SELECT url, status  FROM urls WHERE " + SQL_FILTER)
rows = cursor.fetchall()

if rows == []:
    logger.debug("No new changed URLs")
    exit()
else:
    logger.info(f"Found {len(rows)} URLs with changed status")

logger.debug(rows)

# connect to MISP
misp_url = args.misp_url
api_key = args.key
verify_cert = False
misp = ExpandedPyMISP(misp_url, api_key, verify_cert, debug=True)
logger.debug("Connected to MISP")


# create objects
for row in rows:
    events = misp.search(value=row[0], type_attribute='url', pythonify=True)
    
    for e in events:
        event = misp.get_event(e.id, pythonify=True)
        if type(event) is not MISPEvent:
            logger.info(f"Couldn't find event for URL {row[0]}")
            continue

        if len(event.Object) != 0:
            for i in range(len(event.Object)):
                obj = event.Object[i]
                if obj.name == "url-honeypot-detection":
                    for j in range(len(obj.Attribute)):
                        attr = obj.Attribute[j]
                        if (attr.type == "url" and attr.value == row[0]):
                            if row[1] == "active":
                                event.Object[i].Attribute[j].to_ids = True
                                logger.debug(f"Set to_ids to True for {row[0]}")
                            else:
                                event.Object[i].Attribute[j].to_ids = False
                                logger.debug(f"Set to_ids to False for {row[0]}")
                
        elif len(event.Attribute) != 0:
            for i in range(len(event.Attribute)):
                attr = event.Attribute[i]
                if (attr.value == row[0]):
                    if row[1] == "active":
                        event.Attribute[i].to_ids = True
                        logger.debug(f"Set to_ids to True for {row[0]}")
                    else:
                        event.Attribute[i].to_ids = False
                        logger.debug(f"Set to_ids to False for {row[0]}")
        misp.update_event(event)
    
logger.info("Updated status of URLs in MISP")


# Update database
cursor.execute("UPDATE urls SET status_changed = 'no' WHERE " + SQL_FILTER)
conn.commit()
logger.debug("Updated database")

# Close connection to database
conn.close()
