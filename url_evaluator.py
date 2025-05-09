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

# Dictionary for HTTP proxy
proxies = {}

# Variables for database connection
conn_db = None
cursor_db = None

# Variables for blacklist
bl_last_updated = None

# # Variables for VirusTotal API limit
vt_min_quota = 4
vt_cnt = 0
vt_time_minute = None
vt_quota_exceeded = False
vt_time = None

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

def set_proxies(config: Config):
    global proxies
    if config.http_proxy != "":
        proxies = {
            "http": config.http_proxy,
            "https": config.http_proxy
        }


def is_valid_url(url: str) -> bool:
    regex_pattern = r"^(?:https?:\/\/)?[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[^\s$]*)?(\$[^\s]*)?$"
    return re.match(regex_pattern, url) is not None and "'" not in url and '"' not in url and ',' not in url


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

        updated = False
        while not updated:
            try:
                cursor_db.execute(update_sql, (date, url_in_db[0][0]+1, url))
                conn_db.commit()
                updated = True
            except sqlite3.Error as e:
                logger.info(f"Error while updating URL occurrences: {e}")
                conn_db.rollback()
                time.sleep(1)
        return True

@lru_cache()
def vt_hash_check(hash: str, vt_key: str):
    global vt_cnt
    global vt_time_minute
    global vt_min_quota

    if vt_cnt >= vt_min_quota:
            if vt_time_minute + timedelta(minutes=1) < datetime.now():
                sleep_time = 60 - (datetime.now() - vt_time_minute).seconds
                time.sleep(sleep_time)
            
            vt_cnt = 0
            vt_time_minute = datetime.now()

    vt_url = "https://www.virustotal.com/api/v3/files"
    vt_request = f'{vt_url}/{hash}'
    params = {"apikey": vt_key,
              "resource": hash,
              "scan": 1}
    headers = { "x-apikey": vt_key}
    response = requests.get(vt_request, headers=headers, params=params)
    return response.json()


def evaluate_later(url: str, db_path: str):
    # set URL to evaluate later after VirusTotal API limit is reset
    logger.info(f"Evaluating URL {url} later, after VirusTotal API limit is reset")
    db_connection(db_path)
    updated = False
    while not updated:
        try:
            cursor_db.execute("PRAGMA foreign_keys = ON")
            cursor_db.execute("UPDATE urls SET eval_later='yes' WHERE url=?", (url, ))
            conn_db.commit()
            updated = True
        except sqlite3.Error as e:
            logger.info(f"Error while updating URL to evaluate later: {e}")
            conn_db.rollback()
            time.sleep(1)
    conn_db.close()

def check_hash(url: str, hash: str, file_type: str, content_size: int, config: Config):
    """
    Check hash of downloaded content in VirusTotal and MalwareBazaar.
    Parameters:
        url     : checked URL
        hash    : Hash of downloaded content
        vt_key  : VirusTotal API key
        config  : Config object
    """

    # check hash in VirusTotal
    logger.debug("Checking hash in VirusTotal")
    vt_stats_json = ""
    class_reason = ""
    threat_label = ""
    
    if not vt_quota_exceeded:
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
            add_to_database(url, classification, class_reason, vt_stats_json, hash, content_size, file_type, threat_label, db_path=config.db_path)
            return
    
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

    if vt_quota_exceeded and classification == "unclassified":
        # url will be evaluated later after VirusTotal API limit is reset
        evaluate_later(url, config.db_path)
    else:
        add_to_database(url, classification, class_reason, vt_stats_json, hash, content_size, file_type, threat_label, db_path=config.db_path)


def download_content(url: str, config: Config):
    """
    Download content from given URL and check it.
    Parameters:
        url     : URL to download
        config  : Config object
    """
    global proxies
    logger.debug("Downloading URL")
    try:
        max_bytes = 100 * 1024 * 1024

        # Use GET with stream=True to avoid downloading the whole body
        with requests.get(url, stream=True, proxies=proxies) as r:
            if r.status_code == 503:
                add_to_database(url, "unreachable","Connection refused", "", "", None, "", "", db_path=config.db_path)
                return

            if not r.ok:
                add_to_database(url, "unreachable", f"Return code {r.status_code}", "", "", None, "", "", db_path=config.db_path)
                return
            
            content_length = r.headers.get('Content-Length', None) # get only length of content from headers
            if content_length is None:
                add_to_database(url, "unclassified", "", "", "", None, "", "", db_path=config.db_path)
                return 

            file_size = int(content_length)
            if file_size > max_bytes:
                add_to_database(url, "unclassified", f"File too large: {file_size / (1024 * 1024):.2f} MB", "", "", None, "", "", db_path=config.db_path)

                return None
            content = r.content
            response = r

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as e:
        add_to_database(url, "unreachable", "Connection timeout", "", "", None, "", "", db_path=config.db_path)
        logger.debug(e)
        return
    except requests.exceptions.TooManyRedirects as e:
        add_to_database(url, "unreachable", "Too many redirects", "", "", None, "", "", db_path=config.db_path)
        logger.debug(e)
        return
    except requests.exceptions.ConnectionError as e:
        add_to_database(url, "unreachable", "Connection refused", "", "", None, "", "", db_path=config.db_path)
        logger.debug(e)
        return

    downloaded_size = len(content)

    file_type = ""
    if "content-type" in response.headers.keys():
        file_type = response.headers['content-type'].split(";")[0]
    else:
        try:
            file_type = magic.from_buffer(content, mime=True)
        except Exception as e:
            logger.info(f"Couldn't determine file type. Error: {e}")


    # URL regex
    command_format = r"(.*\b(curl|wget)\b.*https?:\/\/[^\s]+.*)"
    url_format = r"(?<!(--referer|-e)(\s|\s\'|\s\"))(https?:\/\/.*?)(?=\s|;|\\||\\\\|\"|\')"

    types_list = ["application/x-sh", "aplication/x-shellscript", "text/plain", "text/x-shellscript", "text/x-sh"]
    if file_type in types_list:
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
        commands_reg = re.findall(command_format, content) 
        for command in commands_reg:
            command = command[0].strip()
            urls_reg = regex.findall(url_format, command)
            for url_found in urls_reg:
                url_found = url_found[2].strip()
                if is_valid_url(url_found):
                    add_new(url_found, command, url, config)

 
    if isinstance(content, str):
        content = content.encode('utf-8')

    hash = hashlib.sha1(content).hexdigest()

    check_hash(url, hash, file_type, downloaded_size, config)

def is_active(url: str):
    """
    Check if URL is active.
    Parameters:
        url     : URL to check
    """
    try:
        with requests.get(url, stream=True, proxies=proxies, timeout=10) as r:
            if r.ok:
                logger.info(f"URL {url} is active.")
                return True
            else:
                logger.info(f"URL {url} is not active.")
                return False
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
        logger.info(f'Connection error while checking if URL is active: {e}')
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
    inserted = False
    while not inserted:
        try:
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
            inserted = True
        except sqlite3.Error as e:
            logger.info(f"Error while adding new URL to database: {e}")
            conn_db.rollback()
            time.sleep(1)
    conn_db.close()


def back_propagation(url: str, db_path: str):
    db_connection(db_path)

    cursor_db.execute("SELECT urls.url FROM url_source AS s JOIN urls ON urls.url = s.src_url WHERE s.url = ? AND urls.classification != 'malicious'", (url,))
    src_urls = cursor_db.fetchall()
    if len(src_urls) == 0:
        return
    logger.debug(f"URL {url} was found in downloaded content of {len(src_urls)} URLs")

    src_urls = ", ".join(f"'{src_url[0]}'" for src_url in src_urls)

    updated = False 
    while not updated:
        try:
            cursor_db.execute(f"UPDATE urls SET classification = 'malicious', classification_reason = 'Downloading from malicious URL' WHERE url IN ({src_urls})")
            logger.info(f"URL {src_urls} were classified as malicious because it downloaded content from malicious URL {url}")
            conn_db.commit()
            updated = True
        except sqlite3.Error as e:
            logger.info(f"Error while updating URL in database: {e}")
            conn_db.rollback()
            time.sleep(1)

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
            threat_label=?,
            eval_later=NULL
            WHERE url=?;"""

    if not isinstance(threat_label, str):
        threat_label = ""

    db_connection(db_path)
    update = False
    while not update:
        try:
            cursor_db.execute(sql_insert, (hash, classification, classification_reason, "no", vt_stats_json, "yes", file_type, threat_label, url))
            if content_size:
                sql_insert = f"""UPDATE urls SET
                                content_size=?
                                WHERE url=?;"""
                cursor_db.execute(sql_insert, (content_size, url))
            conn_db.commit()
            update = True
        except sqlite3.Error as e:
            logger.info(f"Error while updating URL in database: {e}")
            conn_db.rollback()
            time.sleep(1)

    updated = False
    while not updated:
        try:
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
            updated = True
        except sqlite3.Error as e:
            logger.info(f"Error while updating URL status in database: {e}")
            conn_db.rollback()
            time.sleep(1)

    conn_db.close()

    # if the URL is malicious, check if this URL was found in downloaded content of another URL and if so, update the classification of the source URL
    if classification == "malicious":
        logger.debug(f"Checking if URL {url} was found in downloaded content of another URL")
        back_propagation(url, db_path)

    

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
    global vt_quota_exceeded
    global vt_time
    global vt_time_minute
    global vt_min_quota
    global vt_cnt

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
        
        if vt_quota_exceeded:
            download_content(url, config)
            continue

        if vt_cnt >= vt_min_quota:
            if vt_time_minute + timedelta(minutes=1) < datetime.now():
                sleep_time = 60 - (datetime.now() - vt_time_minute).seconds
                time.sleep(sleep_time)
            
            vt_cnt = 0
            vt_time_minute = datetime.now()

        # check URL in VirusTotal
        with virustotal_python.Virustotal(config.virustotal_key) as vtotal:
            try:
                url_id = urlsafe_b64encode(
                    url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
            except virustotal_python.VirustotalError as err:
                try: 
                    if err.args[0].status_code == 404:
                        logger.info(f"VirusTotal does not have information about URL {url}")
                    elif err.args[0].status_code == 429:
                        logger.info("VirusTotal API limit for the day exceeded")
                        vt_quota_exceeded = True
                        vt_time = datetime.now()
                except (IndexError, AttributeError):
                    logger.info(err)
                
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
    global vt_time_minute
    global vt_quota_exceeded
    global vt_time
    global bl_last_updated
    # global vt_count_day
    global running_flag
    global signals
    global logger
    args = parse_args()

    try:
        config = Config(args.config)
        set_proxies(config)
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


    # last_date = datetime.now().date()

    # Setup signal handlers
    for (signum, handler) in signals.items():
        signal.signal(signum, handler)

    # set vt timer for minute limit check
    vt_time_minute = datetime.now()

    logger.debug("Starting main loop")
    while running_flag:
        if vt_time is not None and vt_time.date() < datetime.now().date():
            vt_time = None
            vt_quota_exceeded = False 

        # Create database connection
        logger.debug(f"Connecting to database at {config.db_path}")
        db_connection(config.db_path)

        # Load URLs from database to list
        url_list = []
        logger.debug(f"Loading URLs from database")
        if vt_quota_exceeded:
            cursor_db.execute("SELECT url FROM urls WHERE evaluated = 'no' AND eval_later != 'yes'")
        else:
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
