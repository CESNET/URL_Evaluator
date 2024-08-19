#!/usr/bin/env python3
import re
import signal

import requests
from pymisp import ExpandedPyMISP
import argparse
import logging
import sys
import os

# parse arguments
parser = argparse.ArgumentParser(description="Get list of URLs (marked with IDS tag) from MISP and write them to a file.")
parser.add_argument("-m", "--misp-url", help="Base URL of the MISP instance", required=True)
parser.add_argument("-k", "--key", help="API key for the MISP instance", required=True)
parser.add_argument("-o", "--outfile", help="Path to the output file", required=True)
parser.add_argument("-p", "--pid", help="Path to the file with pid of process to send signal to")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
args = parser.parse_args()

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
logger = logging.getLogger("MISP Sender")
if args.verbose:
    logger.setLevel("DEBUG")

# get blacklist from URLhaus
abusech_url_list = set()
try:
    response = requests.get("https://urlhaus.abuse.ch/downloads/text_online/")
    if response.status_code == 200:
        for line in response.text.split("\n"):
            if line.startswith("#") or len(line) == 0:
                continue
            abusech_url_list.add(line)
        logger.debug(f"Read {len(abusech_url_list)} URLs from URLhaus")
    else:
        logger.error(f"Failed to get URLs from URLhaus: ({response.status_code}) {response.text[:500]}")
except IOError as e:
    logger.error(f"Failed to get URLs from URLhaus: {e}")

# connect to MISP
misp_url = args.misp_url
api_key = args.key
verify_cert = False # TODO: should be optional, enabled by default
misp = ExpandedPyMISP(misp_url, api_key, verify_cert)
logger.debug(f"Connected to MISP at {misp_url}, reading URL attributes...")

events = misp.search(controller='events', limit=0)

misp_url_list = set() # use set to avoid duplicates
for event in events:
    for attribute in event["Event"]["Attribute"]:
        if attribute["type"] == "url" and attribute["to_ids"] == True:
            misp_url_list.add(attribute["value"])

    for obj in event["Event"]["Object"]:
        if obj["name"] == "url-honeypot-detection":
            for attr in obj["Attribute"]:
                if attr["type"] == "url" and attr["to_ids"] == True:
                    misp_url_list.add(attr["value"])
                    break
logger.debug(f"Read {len(misp_url_list)} URLs from MISP.")

url_list = abusech_url_list | misp_url_list

with open(args.outfile, "w") as f:
    for url in url_list:
        url = url.replace(":80/", "")
        url = re.sub(r':80\b', '', url)
        f.write(url + "\n")

logger.debug(f"Done, {len(url_list)} unique URLs written to {args.outfile}")

# send signal to process of given pid
if args.pid:
    try:
        with open(args.pid, "r") as f:
            pid = int(f.read())
        os.kill(pid, signal.SIGUSR1)
        logger.debug(f"Signal SIGUSR1 sent to process {pid}")
    except (FileNotFoundError,ProcessLookupError) as e:
        logger.error(f"Error sending signal to process: {e}")
