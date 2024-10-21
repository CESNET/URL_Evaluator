#!/usr/bin/env python3
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject, PyMISP
from datetime import datetime
import sqlite3
import logging
import sys
import os
import argparse

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("MISP sender")
logger.setLevel("INFO")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.debug("Logger set")

# Parse arguments
parser = argparse.ArgumentParser(description="Script adding malicious URLs to MISP.")
parser.add_argument("--database", "-d", action="store", required=True,
                    help="Path to a database where URLs are stored")
parser.add_argument("--key", "-k", action="store", required=True,
                    help="API key for URLhaus")
args = parser.parse_args()

# Connection to database
db_path = args.database
if not os.path.exists(db_path):
    logger.error(f"Database file {db_path} does not exist")
    exit()
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
logger.debug("Connected to database")

# get not reported urls
cursor.execute("SELECT url, hash, first_seen, file_mime_type, threat_label, status, classification FROM urls WHERE reported = 'no' and (classification = 'malicious' or classification == 'miner')")
rows = cursor.fetchall()
logger.info(f"Found {len(rows)} new malicious URLs")

if rows == []:
    logger.debug("No new malicious URLs")
    exit()

print(rows)

# connect to MISP
misp_url = "https://misp-soc.liberouter.org"
api_key = args.key  
verify_cert = False
misp = ExpandedPyMISP(misp_url, api_key, verify_cert, debug=False)
logger.debug("Connected to MISP")

# create event
event = MISPEvent()
event.add_tag("tlp:clear")
event.add_tag("coa:discover=honeypot")
event.add_tag('rsit:malicious-code="malware-distribution"')
date = datetime.now().strftime("%Y-%m-%d")
event.info = f"Malicious URLs from SSH honeypots [{date}]"
event.date = date
event.distribution = 3
event.threat_level_id = 3
event.analysis = 2
result = misp.add_event(event)
if result and 'errors' not in result:
    event_id = result.get('Event').get('id')
    # misp.publish(event_id, alert=False)
    logger.info(f'Successfully created event with ID: {event_id}')
else:
    logger.error(f'Failed to create event. Error: {result}')
    conn.close()
    exit()
logger.debug("Created event")

# create objects
for row in rows:
    url = row[0]
    hash = row[1]
    #first_seen = datetime.utcfromtimestamp(row[2]/1000).isoformat()
    first_seen = row[2]
    file_mime_type = row[3]
    threat_label = row[4]
    status = row[5]
    classification = row[6]

    new_object = MISPObject("url-honeypot-discovery", misp_objects_path_custom="/data/url_evaluator/misp_objects/")
    if status == "active":
        url_attr = new_object.add_attribute(object_relation="url", simple_value=url, to_ids=True, Attribute = {"type": "url", "value": url})
    else:
        url_attr = new_object.add_attribute(object_relation="url", simple_value=url, to_ids=False, Attribute = {"type": "url", "value": url, "to_ids":False})
    if classification == "malicious":
        url_attr.add_tag('rsit:malicious-code="malware-distribution"')
    elif classification == "miner":
        url_attr.add_tag('sentinel-threattype:CryptoMining')
    new_object.add_attribute(object_relation="first-seen", simple_value=first_seen, Attribute = {"type": "datetime", "value": first_seen})
    if hash:
        hash_attr = new_object.add_attribute(object_relation="hash", simple_value=hash, Attribute = {"type": "sha1", "value": hash})
    if file_mime_type:
        new_object.add_attribute(object_relation="mime-type", simple_value=file_mime_type, Attribute = {"type": "mime-type", "value": file_mime_type})
    if threat_label:
        new_object.add_attribute(object_relation="threat-label", simple_value=threat_label, Attribute = {"type": "text", "value": threat_label})
    misp.add_object(event=event, misp_object=new_object)
logger.debug("Added objects to event")

# updated_event = misp.update_event(event)

# Publish the event
misp.publish(event_id, alert=True)

# Update database
cursor.execute("UPDATE urls SET reported = 'yes' WHERE reported = 'no' AND classification = 'malicious'")
conn.commit()
logger.debug("Updated database")

# Close connection to database
conn.close()
