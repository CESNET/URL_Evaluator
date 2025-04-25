import argparse
import logging
import threading
import requests
import sqlite3
import time
import sys
from datetime import datetime, timedelta

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
logger = logging.getLogger("activity_status")
logger.setLevel("DEBUG")
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(LOGFORMAT)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Parse arguments
parser = argparse.ArgumentParser(description="Test each URL whether it's active (accessible) or not and set the corresponding flag in database.")
parser.add_argument("--database", "-d", action="store", default="", required=True,
                    help="Path to a database where URLs are stored")
parser.add_argument("--proxy", "-p", action="store", default="", required=True,
                    help="Proxy to connect to URLs.")
args = parser.parse_args()

proxies = {}


def retry_connection(db_path, logger):
    conn = None
    for i in range(5):
        try:
            conn = sqlite3.connect(db_path)
        except sqlite3.OperationalError as e:
            logger.debug(f'Connection error: {e}')
            time.sleep(i)
    return conn


def is_url_active(url, logger):
    try:
        with requests.get(url, stream=True, proxies=proxies, timeout=10) as r:
            return r.status_code < 400
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
        logger.debug(f'Connection error: {e}')
        return False


def get_urls(db_path: str, logger):
    conn = retry_connection(db_path, logger)
    if conn is None:
        logger.error('Could not connect to database')
        return []
    c = conn.cursor()
    c.execute("SELECT url, status, last_active FROM urls")
    urls = c.fetchall()
    conn.close()
    return urls


def update_date(db_path: str, url: str, logger):
    conn = retry_connection(db_path, logger)
    if conn is None:
        logger.error('Could not connect to database for updating date')
        return
    c = conn.cursor()
    day = datetime.now().date()
    c.execute("UPDATE urls SET last_active = ? WHERE url = ?", (day, url))
    conn.commit()
    conn.close()


def update_url_status(db_path: str, url: str, active: bool, change: bool, logger):
    conn = retry_connection(db_path, logger)
    if conn is None:
        logger.error('Could not connect to database for updating status')
        return
    c = conn.cursor()
    day = datetime.now().date()
    if active:
        c.execute("UPDATE urls SET status = 'active', last_active = ? WHERE url = ?", (day, url))
    else:
        c.execute("UPDATE urls SET status = 'inactive' WHERE url = ?", (url,))
    conn.commit()

    if change:
        c.execute("UPDATE urls SET status_changed = 'yes' WHERE url = ?", (url,))
    conn.commit()
    conn.close()


def check_active_urls(config, urls, logger):
    for url in urls:
        active = is_url_active(url[0], logger)
        change = False
        if (active and url[1] == 'inactive') or (not active and url[1] == 'active'):
            logger.info(f'{url[0]} status changed, updating status')
            change = True

        last_active = url[2]

        if last_active is None:
            update_date(config.database, url[0], logger)

        update_url_status(config.database, url[0], active, change, logger)

    logger.info('Finished checking URLs in one thread')


def main():
    global proxies

    args = parser.parse_args()
    end = False
    url_limit = 1000

    first = 0

    proxies = {
            "http": args.proxy,
            "https": args.proxy
        }

    # Load data from the database
    urls = get_urls(args.database, logger)
    urls_len = len(urls)
    logger.info(f"Found {urls_len} URLs")

    while not end:
        if first + url_limit >= len(urls):
            end = True
            url_limit = urls_len - first
        logger.info(f'First: {first}, last: {first+url_limit}')

        url_list = urls[first:first+url_limit]

        # Start a new thread to run the program
        thread = threading.Thread(target=check_active_urls, args=(args, url_list, logger))
        thread.start()

        first += url_limit
    


if __name__ == '__main__':
    main()