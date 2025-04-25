#!/usr/bin/env python3
import argparse

import requests
from pymisp import ExpandedPyMISP, MISPEvent
import logging
import sys

# parse arguments
parser = argparse.ArgumentParser(description="Actively test responsibility of malicious URLs in MISP and set the to_ids flag accordingly.")
parser.add_argument("-m", "--misp-url", help="Base URL of the MISP instance", required=True)
parser.add_argument("-k", "--key", help="API key for the MISP instance", required=True)
args = parser.parse_args()

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("MISP active URL")
logger.setLevel("INFO")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


# connect to MISP
misp_url = args.misp_url
api_key = args.key
verify_cert = False
misp = ExpandedPyMISP(misp_url, api_key, verify_cert, debug=True)
logger.debug("Connected to MISP")



events = misp.search(controller='events', limit=0, pythonify=True)

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
                    if (attr.type == "url"):
                        active = True
                        try:
                            response = requests.head(attr.value, timeout=5)
                            if response.status_code >= 400:
                                active = False
                        except (requests.exceptions.RequestException) as e:
                            active = False
                        if not active:
                            event.Object[i].Attribute[j].to_ids = False
                            logger.debug(f"Set to_ids to False for {attr.value}")
            
    elif len(event.Attribute) != 0:
        for i in range(len(event.Attribute)):
            attr = event.Attribute[i]
            if (attr.type == "url"):
                active = True
                try:
                    response = requests.head(attr.value, timeout=5)
                    if response.status_code >= 400:
                        active = False
                    else:
                        logger.debug(f"URL {attr.value} is active")
                except (requests.exceptions.RequestException) as e:
                    active = False
                if not active:
                    event.Attribute[i].to_ids = False
                    logger.debug(f"Set to_ids to False for {attr.value}")
            
    try: 
        misp.update_event(event)
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't update event {event.id}: {e}")
        continue

logger.info("Updated status of URLs in MISP")

