#!/usr/bin/env python3
import os
import re
import signal
import regex
import sys
import json
import time
import argparse
import sqlite3
import hashlib
import magic
import requests
import logging
import datetime as dt

import yaml
import virustotal_python
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from modules.load_config import Config
from sqlite3 import Error
from functools import lru_cache

# Variables for database connection
conn_db = None
cursor_db = None

# Variables for blacklist
bl_last_updated = None

# Variables for VirusTotal API limit
vt_limit_minute = 4
vt_count_minute = 0
vt_start = None
vt_limit_day = 500
vt_count_day = 0

# logger
logger = None

# variables for signal handling
def terminate_me(signum, frame):
    global running_flag
    running_flag = False

running_flag = True
signals = {
    signal.SIGTERM: terminate_me,
    signal.SIGINT: terminate_me,
}


def is_valid_url(url: str) -> bool:
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return re.match(regex, url) is not None and "'" not in url and '"' not in url and ',' not in url


def db_connection(db_path):
    """
    Connects to a SQLite database.
    Parameters:
        db_path (str): The path to the database file.
    """

    global conn_db
    global cursor_db

    connected = False
    # Create database connection
    while not connected:
        try:
            conn_db = sqlite3.connect(db_path)
            connected = True
        except Error as e:
            logger.debug(e)
            logger.info(f"Error while connecting to database: {e}")
            time.sleep(1)

    # Enable foreign keys
    conn_db.execute("PRAGMA foreign_keys = ON")
    # Create a cursor
    cursor_db = conn_db.cursor()


def is_in_database(url: str) -> bool:
    """
    Check if given URL is already in database. 
    If it is in database function returns classification of this URL, if not returns None.
    Parameters:
        url     : URL to find in database
    """
    select_sql = f"SELECT url_occurrences, evaluated FROM urls WHERE url='{url}'"
    cursor_db.execute(select_sql)
    url_in_db = cursor_db.fetchall()
    if not url_in_db or url_in_db[0][1] == "no":
        return False
    else:
        date = datetime.date(datetime.utcnow())
        update_sql = f"UPDATE urls SET last_seen=?, url_occurrences=? WHERE url=?;"
        cursor_db.execute(update_sql, (date, url_in_db[0][0]+1, url))
        cursor_db.fetchall()
        return True


def check_vt_limit():
    """
    Check VirusTotal API limit.
    """
    global vt_count_minute
    global vt_start
    global vt_count_day

    if time.time() - vt_start < 60:
        if vt_count_minute >= vt_limit_minute:
            time.sleep(60 - (time.time() - vt_start))
            vt_start = time.time()
            vt_count_minute = 0
    else:
        vt_count_minute = 0
        vt_start = time.time()

    vt_count_minute += 1
    vt_count_day += 1

@lru_cache()
def vt_hash_check(hash: str, vt_key: str):
    vt_url = "https://www.virustotal.com/api/v3/files"
    vt_request = f'{vt_url}/{hash}'
    params = {"apikey": vt_key,
              "resource": hash,
              "scan": 1}
    headers = { "x-apikey": vt_key}
    response = requests.get(vt_request, headers=headers, params=params)
    return response.json()


def check_hash(url: str, hash: str, file_type: str, content_size: str, config: Config):
    """
    Check hash of downloaded content in VirusTotal and MalwareBazaar.
    Parameters:
        url     : checked URL
        hash    : Hash of downloaded content
        vt_key  : VirusTotal API key
        config  : Config object
    """

    # check_vt_limit()

    # check hash in VirusTotal
    logger.debug("Checking hash in VirusTotal")
    vt_stats_json = ""
    class_reason = ""
    threat_label = ""
    
    response_json = vt_hash_check(hash, config.virustotal_key)

    if response_json.get("data", {}).get("attributes", {}):
        attributes = response_json.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", {})
        if stats["malicious"] > config.limits["malicious"]:
            classification = "malicious"
            class_reason = "Hash control"
        elif (stats["malicious"] == 0 and stats["suspicious"] == 0 and stats["undetected"] == 0 and stats["harmless"] > 0):
            classification = "harmless"
        else: 
            classification = "unclassified"
        vt_stats_json = json.dumps(stats)
    else:
        # check hash in MalwareBazaar
        logger.debug("Checking hash in MalwareBazaar")
        response = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": hash})
        response_json = response.json()
        if response_json["query_status"] == "ok":
            # add_to_database(url, "malicious", "Hash control", "", hash)
            classification = "malicious"
            class_reason = "Hash control"
            return
        else:
            classification = "unclassified"

    add_to_database(url, classification, class_reason, vt_stats_json, hash, content_size, file_type, threat_label, db_path=config.db_path)


def download_content(url: str, config: Config):
    """
    Download content from given URL and check it.
    Parameters:
        url     : URL to download
        config  : Config object
    """
    logger.debug("Downloading URL")
    try:
        header = requests.head(url, timeout=20)
        if header.status_code >= 400:
            add_to_database(url, "unreachable", f"Return code {header.status_code}", "", "", None, "", "", db_path=config.db_path)
            return
        
        if "content-length" in header.headers.keys():
            content_size = int(header.headers['content-length'])
            content_size_mb = content_size / (1024 * 1024)
            logger.debug(f"Content size: {content_size_mb:.2f} MB")
            if content_size_mb > 100:
                add_to_database(url, "unclassified", "Content too big (>100MB)", "", "", content_size, "", "", db_path=config.db_path)
                return

        response = requests.get(url, timeout=20, stream=True)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
        add_to_database(url, "unreachable", "Connection timeout", "", "", None, "", "", db_path=config.db_path)
        logger.debug(e)
        return
    except requests.exceptions.ConnectionError as e:
        add_to_database(url, "unreachable", "Connection refused", "", "", None, "", "", db_path=config.db_path)
        logger.debug(e)
        return

    downloaded_size = len(response.content)

    file_type = ""
    if "content-type" in response.headers.keys():
        file_type = response.headers['content-type'].split(";")[0]
    else:
        try:
            file_type = magic.from_buffer(response.content, mime=True)
        except Exception as e:
            logger.info(f"Couldn't determine file type. Error: {e}")


    # URL regex
    command_format = r"(.*\b(curl|wget)\b.*https?:\/\/[^\s]+.*)"
    url_format = "(?<!(--referer|-e)(\s|\s\'|\s\"))(https?:\/\/.*?)(?=\s|;|\\||\\\\|\"|\')"

    if "x-sh" in file_type or "sh" in file_type or "bash" in file_type or "shell" in file_type or "plain" in file_type:
        try:
            content = response.content.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
        commands_reg = re.findall(command_format, content) 
        for command in commands_reg:
            command = command[0].strip()
            urls_reg = regex.findall(url_format, command)
            for url_found in urls_reg:
                add_new(url_found[2].strip(), command, url, config)

 

    hash = hashlib.sha1(response.content).hexdigest()

    check_hash(url, hash, file_type, downloaded_size, config)

def is_active(url: str):
    """
    Check if URL is active.
    Parameters:
        url     : URL to check
    """
    try:
        response = requests.head(url, timeout=20)
        if response.status_code >= 400:
            return False
        else:
            return True
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
        return False
    except requests.exceptions.ConnectionError:
        return False

def add_new(url: str, command: str, src_url: str, config: Config):
    """
    If new URL was found in a shell script add the new URL to database.
    Parameters:
        url     : URL to add
        command : command that contains URL
        config  : Config object
    """
    
    logger.info(f"New URL ({url}) found in a script on {src_url}")
     
    if is_active(url):
        status = "active"
    else:
        status = "inactive"

    # time of detection
    first_seen = datetime.now(dt.timezone.utc).date()

    command_id = hashlib.md5(command.encode()).hexdigest()

    db_connection(config.db_path)
    # insert new URL to database
    cursor_db.execute("PRAGMA foreign_keys = ON")
    sql_insert = "INSERT OR IGNORE INTO urls (url, first_seen, url_occurrences, reported, evaluated, status, last_active) VALUES (?, ?, ?, ?, ?, ?, ?)"
    cursor_db.execute(sql_insert, (url, first_seen, 0, "no", "no", status, first_seen))
    cursor_db.execute("UPDATE urls SET url_occurrences = url_occurrences + 1, last_seen = ?  WHERE url = ?", (first_seen, url))
    cursor_db.execute("INSERT OR IGNORE INTO url_source (url, src_url) VALUES (?, ?)", (url, src_url))
    
    # add session to database
    cursor_db.execute("INSERT OR IGNORE INTO sessions (session_hash, session) VALUES (?, ?)", (command_id, command))
    cursor_db.execute("INSERT OR IGNORE INTO url_session (url, session) VALUES (?, ?)", (url, command_id))

    # set number of occurrences
    conn_db.commit()
    conn_db.close()


def add_to_database(url: str, classification: str, classification_reason: str, vt_stats_json, hash: str, content_size: int, file_type: str, threat_label: str, db_path: str):
    """
    Add classified URL to database.
    Parameters:
        url                     : URL to add
        classification          : classification of URL
        classification_reason   : reason of classification
        vt_stats_json           : JSON with VirusTotal statistics
        hash                    : hash of downloaded content
    """
    logger.info(f'URL {url} was classified as "{classification}" (reason: "{classification_reason}")')
    sql_insert = f"""UPDATE urls SET
            hash=?,
            classification=?,
            classification_reason=?,
            reported=?,
            vt_stats=?,
            evaluated=?,
            file_mime_type=?,
            threat_label=?
            WHERE url=?;"""

    if not isinstance(threat_label, str):
        threat_label = ""

    db_connection(db_path)
    cursor_db.execute(sql_insert, (hash, classification, classification_reason, "no", vt_stats_json, "yes", file_type, threat_label, url))
    conn_db.commit()

    if content_size:
        sql_insert = f"""UPDATE urls SET
            content_size=?
            WHERE url=?;"""
        cursor_db.execute(sql_insert, (content_size, url))
        conn_db.commit()

    # check if URL is active
    if is_active(url):
        status = "active"
        last_active = datetime.now(dt.timezone.utc).date()
    else:
        status = "inactive"
        last_active = cursor_db.execute("SELECT last_active FROM urls WHERE url = ?", (url,)).fetchone()[0]
        if not last_active:
            last_active = datetime.now(dt.timezone.utc).date()
        cursor_db.execute("UPDATE urls SET status = ? WHERE url = ?", (status, url))
    cursor_db.execute("UPDATE urls SET status = ?, last_active = ? WHERE url = ?", (status, last_active, url))

    conn_db.commit()

    conn_db.close()
    

def get_blacklist(config: Config):
    """
    Load blacklist from file. Requires blacklist to be downloaded before running evaluator. 
    (You can download blacklist by running "curl https://urlhaus.abuse.ch/downloads/text/ --create-dirs-o /data/url_evaluator/Blacklists/blacklist.txt")
    Parameters:
        config  : Config object
    """
    # check valid path to blacklist file
    if not os.path.isfile(config.bl_path):
        logger.error("Blacklist file not found")
        exit()
        
    # load blacklist file
    bl_list = []
    with open(config.bl_path, "r") as bl_file:
        for line in bl_file:
            if not line.strip().startswith("#"):
                bl_list.append(line.strip())
    return bl_list


def check_urls(url_list: list, config: Config, bl_list: list):
    """
    Check URLs from list.
    Parameters:
        url_list    : list of URLs to check
        config      : Config object
        bl_list     : list of URLs in blacklist
    """

    global running_flag
    global vt_start
    vt_start = time.time()

    with virustotal_python.Virustotal(config.virustotal_key) as vtotal:
        for url in url_list:
            if not running_flag:
                break
            logger.info(f"URL: {url}")

            # check if URL is valid
            if not is_valid_url(url):
                add_to_database(url, "invalid", "Invalid URL", "", "", None, "", "", db_path=config.db_path)
                continue

            # check in URLhaus blacklist
            if url in bl_list:
                add_to_database(url, "malicious", "blacklist check", "", "", None, "", "", db_path=config.db_path)
                continue
            
            # if VT limit for a day is reached, skip 
            if vt_count_day >= vt_limit_day:
               continue

            check_vt_limit()

            # check URL in VirusTotal
            try:
                url_id = urlsafe_b64encode(
                    url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
            except virustotal_python.VirustotalError as err:
                logger.info(
                    f"Failed to send URL: {url} for analysis and get the report: {err}")
                download_content(url, config)
                continue

            # get responses from VirusTotal report
            report_attributes = report.data["attributes"]
            report_stats = report_attributes["last_analysis_stats"]

            # get threshold values from config
            malicious_lim = config.limits["malicious"]

            # get ratio of malicious detections
            stats_count = sum(report_stats.values())
            if stats_count == 0:
                malicious_ratio = 0
            else:
                malicious_ratio = report_stats["malicious"] / stats_count

            # check thresholds
            if (malicious_ratio > malicious_lim):
                vt_stats_json = json.dumps(report_stats)
                add_to_database(url, "malicious", "VirusTotal URL check", vt_stats_json, "", None, "", "", db_path=config.db_path)
            else:
                download_content(url, config)
           

def parse_args():
    """
    Parse arguments from command line.
    """
    parser = argparse.ArgumentParser(
                    prog='url_evaluator.py',    
                    description='Program checks given URLs, analyze them and saves informations to database')
    parser.add_argument('--config', '-c', action='store', default="", required=True,
                    help='Path to a file with URLs')
    args = parser.parse_args()
  
    return args


def main():
    """
    Connect to database, load URLs from file and call function to check them.
    """
    
    global bl_last_updated
    global vt_count_day
    global running_flag
    global signals
    global logger
    args = parse_args()

    try:
        config = Config(args.config)
    except (FileNotFoundError, yaml.YAMLError):
        print("Error while loading configuration file", file=sys.stderr)
        exit(1)

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    if config.log_file:
        logging.basicConfig(filename=config.log_file, filemode="a", format=LOGFORMAT, level=logging.INFO)
    else:
        logging.basicConfig(format=LOGFORMAT, level=logging.INFO)
        print("No log file specified, logging to stdout")
    logger = logging.getLogger("URL Evaluator")
    logger.info("Starting URL Evaluator")

    if not config.virustotal_key:
        logger.fatal("VirusTotal API key not set in configuration.")
        sys.exit(1)

    if not os.path.isfile(config.db_path):
        logger.fatal(f"Database file {config.db_path} not found")
        sys.exit(1)


    last_date = datetime.now().date()

    # Setup signal handlers
    for (signum, handler) in signals.items():
        signal.signal(signum, handler)

    logger.debug("Starting main loop")
    while running_flag:
        if last_date != datetime.now().date():
            last_date = datetime.now().date()
            vt_count_day = 0

        if vt_count_day >= vt_limit_day:
            logger.info("VirusTotal API limit for a day reached")
            time.sleep(60)
            continue

        # Create database connection
        logger.debug(f"Connecting to database at {config.db_path}")
        db_connection(config.db_path)

        # Load URLs from database to list
        url_list = []
        logger.debug(f"Loading URLs from database")
        cursor_db.execute("SELECT url FROM urls WHERE evaluated = 'no'")
        url_list_db = cursor_db.fetchall()

        # Close database connection
        conn_db.close()

        if len(url_list_db) == 0:
            logger.debug("No URLs to check")
            time.sleep(60)
            continue
        else:
            logger.info(f"Loaded {len(url_list_db)} URLs from database")
            for url in url_list_db:
                url_list.append(url[0])

        # Get blacklist
        if not bl_last_updated or bl_last_updated + timedelta(minutes=config.bl_update_time) < datetime.now():        
            bl_last_updated = datetime.now()
            logger.info(f"Getting blacklist at {config.bl_path}")
            bl_list = get_blacklist(config)

        # Check URLs from file
        logger.info("Checking URLs ...")
        
        check_urls(url_list, config, bl_list)

    logger.info("Exiting ...")
    exit()


if __name__ == "__main__":
    main()
