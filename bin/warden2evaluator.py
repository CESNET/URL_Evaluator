#!/usr/bin/env python3

import signal
import sys
import os
import argparse
import logging
import time
import regex as re
from warden_client import Client, Error, read_cfg

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import process_new_session


def get_source_name(event):
    """
    Get name of the URL source based on Warden source mapping config
    Returns first source where the event matches any pattern, or None if no match is found
    """
    for source, rules in warden_sources.items():
        if not rules:
            return source
        for field_path, pattern in rules.items():
            if any(pattern.search(val) for val in get_idea_field(event, field_path)):
                return source
    return None


def get_idea_field(event, field_path):
    """
    Extract values from the specified IDEA path
    """
    keys = field_path.split(".")
    values = [event]
    for key in keys:
        next_values = []
        for val in values:
            if isinstance(val, dict) and key in val:
                next_values.append(val[key])
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and key in item:
                        next_values.append(item[key])
        values = next_values
    flattened = []
    for val in values:
        if isinstance(val, list):
            flattened.extend(str(v) for v in val if isinstance(v, (str, int)))
        elif isinstance(val, (str, int)):
            flattened.append(str(val))
    return flattened


def receiver():
    """
    Receive messages from Warden
    """

    while running_flag:
        if not (events := wclient.getEvents(**config.warden_filter)):
            time.sleep(10)
            continue
        logger.debug("Received %d events", len(events))

        with SQLiteWrapper(config.db_path) as db:
            for event in events:
                if not (source := get_source_name(event)):
                    continue
                for attachment in event.get("Attach", []):
                    if "Content" in attachment:
                        content = attachment["Content"]
                        if re.match("^\[(\'|\")(\r\n|\r|\n|.)*(\'|\")\]$", content):
                            content = content[2:-2]  # Unwrap
                        logger.debug(f"Looking for new URLs in '{content}'")

                        # Search for new URLs
                        if new_urls := process_new_session(db, config, content, event.get("ID"), event.get("DetectTime"), source, None):
                            logger.info(f"Discovered {len(new_urls)} new URLs (event ID {event.get('ID')}): {new_urls}")


def sigint_handler(signum, frame):
    global running_flag
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    running_flag = False


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Receives messages from Warden, extracts suspicious URLs and stores them into Evaluator DB")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("warden2evaluator.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Compile patterns for Warden source mapping
    warden_sources = {
        source: {field: re.compile(pattern) for field, pattern in rules.items()}
        for source, rules in config.warden_sources.items()
    }

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    # Run Warden client
    logger.info("Started")
    running_flag = True
    wclient = Client(**read_cfg(config.warden_config))
    receiver()
    logger.info("Stopped")
