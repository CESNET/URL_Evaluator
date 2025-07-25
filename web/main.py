import math
import re
import flask
import requests
import os
import sys
import argparse
import logging

from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, make_response, redirect, url_for
from werkzeug.exceptions import BadRequestKeyError
from pymisp import PyMISP, PyMISPError

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import is_valid

# Global variables
page = 1
rows_per_page = 25
filters = ""
filter_params = {}

# Parse arguments
parser = argparse.ArgumentParser(description="Receive messages from Warden, find suspicious URLs and save them to evaluator database.")
parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
args = parser.parse_args()

# Set logger
LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("main.py")
if args.verbose:
    logger.setLevel('DEBUG')

# Load config
config = Config(args.config)

# Connect to MISP
try:
    misp = PyMISP(config.misp_url, config.misp_key, config.misp_verify_cert)
except Exception as e:
    print(f"Error: Cannot connect to MISP: {e}")

# Init flask
application = app = Flask(__name__)
app.secret_key = config.flask_secret_key


def get_urlhaus_link(url):
    response = requests.post(config.urlhaus_detail_url, {'url': url})
    try:
        json_response = response.json()
    except (ValueError, requests.exceptions.RequestException):
        return None
    if json_response['query_status'] == 'ok':
        return json_response['urlhaus_reference']
    else:
        return None


def get_misp_link(url_detail):
    if url_detail.reported == "yes":
        try:
            events = misp.search(controler="events", value=url_detail.url, type_attribute='url')
            event_id = events[0]['Event']['id']
        except Exception:
            return None
        return f"{config.misp_url}/events/view/{event_id}"
    else:
        return None


def get_user(environ):
    # Get name of logged-in user
    if "OIDC_CLAIM_preferred_username" in environ:
        # Get "preferred_username" and "name" from the OIDC claims.
        # Note: fields are encoded in 'latin1' encoding (the old mod_auth_openidc version we have doesn't allow to change it), but read into a Python unicode string - we need to encode it back and decode correctly.
        user = f"{environ['OIDC_CLAIM_preferred_username'].encode('latin1').decode('utf-8')} " \
               f"({environ.get('OIDC_CLAIM_name').encode('latin1').decode('utf-8')})"
    elif "REMOTE_USER" in environ:
        user = environ['REMOTE_USER']
    else:
        user = "--unknown--"
    return user


def get_ip(url):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_address = re.findall(ip_pattern, url)
    if ip_address:
        return ip_address[0]
    else:
        return ""


def parse_filters():
    parsed_filters = " WHERE url NOT NULL"
    for param, value in filter_params.items():
        if param == "order" or param == "order_key" or value == "":
            continue
        if param == "classification":
            parsed_filters += f" AND classification='{value}'"
        if param == "url":
            parsed_filters += f" AND url LIKE '%{value}%'"
        if param == "hash":
            parsed_filters += f" AND hash LIKE '%{value}%'"
        if param == "note":
            parsed_filters += f" AND note LIKE '%{value}%'"
        if param == "reason":
            parsed_filters += f" AND classification_reason LIKE '%{value}%'"
        if param == "status":
            parsed_filters += f" AND status='{value}'"
        if param == "src":
            parsed_filters += f" AND url IN (SELECT url FROM url_source WHERE source='{value}')"
        if param == "evaluated":
            parsed_filters += f" AND evaluated='{value}'"
    parsed_filters += f" ORDER BY {filter_params['order_key']} {filter_params['order']}"
    return parsed_filters


def back_propagation(db, url):
    src_urls = db.execute("SELECT urls.url FROM discovered_urls AS s JOIN urls ON urls.url = s.src_url WHERE s.url = ? AND urls.classification != 'malicious'", (url,)).fetchall()
    if src_urls:
        src_urls = ", ".join(f"'{src_url[0]}'" for src_url in src_urls)
        db.execute(f"UPDATE urls SET classification = 'malicious', classification_reason = 'Downloading from malicious URL' WHERE url IN ({src_urls})")


@app.route('/', methods=['GET', 'POST'])
def list_all():
    global page
    global filter_params

    user = get_user(flask.request.environ)

    # clear filters
    clear = flask.request.args.get('clear_filters')
    if clear == "True":
        filter_params = {}

    # get current page
    page_arg = flask.request.args.get('page')
    if page_arg:
        page = int(page_arg)

    # variables for adding new url
    adding = ""

    # set filters
    if flask.request.method == 'POST':
        try:
            find_url = flask.request.form['find-url'].strip()
            filter_params["url"] = find_url

            find_hash = flask.request.form['find-hash'].strip()
            filter_params["hash"] = find_hash

            find_note = flask.request.form['find-note'].strip()
            filter_params["note"] = find_note

            find_reason = flask.request.form['find-reason'].strip()
            filter_params["reason"] = find_reason

            filter_class = flask.request.form['classification'].strip()
            filter_params["classification"] = filter_class

            filter_status = flask.request.form['status'].strip()
            filter_params["status"] = filter_status

            filter_src = flask.request.form['src'].strip()
            filter_params["src"] = filter_src
        except BadRequestKeyError:
            pass

        # add new url
        try:
            if (add_url := flask.request.form['add-url'].strip()) and is_valid(add_url):
                with SQLiteWrapper(config.db_path) as db:
                    t_now = datetime.now(timezone.utc).strftime('%Y-%m-%d')
                    in_db = db.execute("SELECT url, occurrences FROM urls WHERE url = ?", (add_url,)).fetchall()
                    if not in_db:
                        db.execute("INSERT INTO urls (url, first_seen, last_seen) VALUES (?, ?, ?)", (add_url, t_now, t_now))
                        db.execute("INSERT OR IGNORE INTO url_source (url, source) VALUES (?, ?)", (add_url, "Manual"))
                        adding = "success"
                    else:
                        adding = "in_db"
            else:
                adding = "fail"
        except BadRequestKeyError:
            pass

    if (show := flask.request.args.get('show')) == "not_evaluated":
        filter_params["evaluated"] = "no"
    elif show == "malicious":
        filter_params["classification"] = "malicious"
    elif show == "unclassified":
        filter_params["classification"] = "unclassified"
        filter_params["evaluated"] = "yes"

    # set order of the list
    order = flask.request.args.get("order", "desc")
    order_key = flask.request.args.get("key", "last_seen")

    filter_params["order"] = order
    filter_params["order_key"] = order_key
    filters = parse_filters()

    with SQLiteWrapper(config.db_path) as db:
        # get url details
        url_list = db.execute("SELECT url, first_seen, last_seen, occurrences, classification, classification_reason, note, status FROM urls" + filters + f" LIMIT {rows_per_page} OFFSET {rows_per_page * (page - 1)}").fetchall()

        # get list of sources
        sources = db.execute("SELECT DISTINCT source FROM url_source").fetchall()

        # get number of pages
        record_count = db.execute("SELECT COUNT(*) FROM urls" + filters).fetchall()[0][0]
        page_count = math.ceil(record_count / rows_per_page) if record_count > 0 else 1

    return render_template('list_all.html', user=user, url_list=url_list, order=order, key=order_key, show=show, adding=adding, page=page, page_count=page_count, filter_params=filter_params, sources=sources)


class URLDetail:
    def __init__(self, url_detail):
        self.url = url_detail[0]
        self.first_seen = url_detail[1]
        self.last_seen = url_detail[2]
        self.hash = url_detail[3]
        self.classification = url_detail[4]
        self.reason = url_detail[5]
        self.note = url_detail[6]
        self.reported = url_detail[7]
        self.occurrences = url_detail[8]
        self.vt_stats = url_detail[9]
        self.evaluated = url_detail[10]
        self.mime = url_detail[11]
        self.content_size = url_detail[12]
        self.threat_label = url_detail[13]
        self.status = url_detail[14]
        self.last_active = url_detail[15]
        self.last_edit = url_detail[16]
        self.eval_later = url_detail[17]
        self.ip = get_ip(self.url)
        self.src = []
        self.src_urls = []
        self.contained_urls = []


@app.route('/detail', methods=['GET', 'POST'])
def detail():
    user = get_user(flask.request.environ)
    show = flask.request.args.get('show')
    url = flask.request.args.get('url')

    with SQLiteWrapper(config.db_path) as db:
        if flask.request.method == 'POST':
            db.execute("UPDATE urls SET evaluated = 'no' WHERE url = ?", (url,))
            return redirect(url_for('detail', url=url))

        # get url details
        url_detail = URLDetail(db.execute("SELECT url, first_seen, last_seen, hash, classification, classification_reason, note, reported, occurrences, vt_stats, evaluated, file_mime_type, content_size, threat_label, status, last_active, last_edit, eval_later FROM urls WHERE url = ? LIMIT 1", (url,)).fetchone())
        url_detail.src = [row[0] for row in db.execute("SELECT source FROM url_source WHERE url = ?", (url,)).fetchall()]
        url_detail.src_urls = db.execute("SELECT src_url FROM discovered_urls WHERE url = ?", (url_detail.url,)).fetchall()
        url_detail.contained_urls = db.execute("SELECT url FROM discovered_urls WHERE src_url = ?", (url,)).fetchall()
        sessions = db.execute("SELECT sessions.session, sessions.idea_id FROM sessions JOIN url_session ON url_session.session=sessions.session_hash WHERE url_session.url = ?", (url,)).fetchall()

    # count not active days
    inactive_for = 0
    if url_detail.status == 'inactive' and url_detail.last_active:
        inactive_for = (datetime.now(timezone.utc).date() - datetime.strptime(url_detail.last_active, '%Y-%m-%d').date()).days

    # get link for external sources
    reason_link = None
    if url_detail.reason == "Blacklist check":
        reason_link = get_urlhaus_link(url)
    elif "VT" in url_detail.reason:
        reason_link = f"https://www.virustotal.com/gui/file/{url_detail.hash}"

    # get link for misp if reported
    misp_link = get_misp_link(url_detail)

    # links for sandboxes
    links = {
        "misp": misp_link,
        "reason-link": reason_link,
        "joe-sandbox": f"https://www.joesandbox.com/analysis/search?q={url_detail.hash}"
    }

    return render_template('detail.html', user=user, url=url_detail, sessions=sessions, show=show, links=links, inactive_for=inactive_for)


@app.route('/edit_detail', methods=['GET', 'POST'])
def edit_detail():
    user = get_user(flask.request.environ)
    url = flask.request.args.get('url')
    show = flask.request.args.get('show')

    with SQLiteWrapper(config.db_path) as db:
        if flask.request.method == 'POST':
            note = flask.request.form['note']
            classification = flask.request.form['class']
            reason = flask.request.form['reason']
            evaluated = "yes" if classification != "unclassified" else "no"
            db.execute("UPDATE urls SET note = ?, classification = ?, classification_reason = ?, last_edit = ?, evaluated = ? WHERE url = ?", (note, classification, reason, user, evaluated, url))
            if classification == "malicious":
                back_propagation(db, url)
            return redirect(url_for("list_all", show=show))

        url_list = db.execute("SELECT * FROM urls WHERE url = ? LIMIT 1", (url,)).fetchall()

    return render_template('edit_detail.html', user=user, url=url_list[0], show=show)


@app.route('/bulk_edit', methods=['GET', 'POST'])
def bulk_edit():
    user = get_user(flask.request.environ)
    action = flask.request.form.get("action")
    if action == "reevaluate":
        selected_urls = flask.request.form.getlist('selected_urls_list[]')
        if selected_urls:
            urls_string = "('" + "', '".join(selected_urls) + "')"
            with SQLiteWrapper(config.db_path) as db:
                db.execute(f"UPDATE urls SET evaluated = 'no' WHERE url IN {urls_string}")
        return redirect(url_for("list_all"))

    selected_urls = flask.request.form.getlist('selected_urls_list[]')
    return render_template('bulk_edit.html', selected_urls=selected_urls, user=user)


@app.route('/bulk_edit_action', methods=['POST'])
def bulk_edit_action():
    user = get_user(flask.request.environ)
    selected_urls = flask.request.form.getlist('selected_urls_list[]')
    note = flask.request.form['note']
    classification = flask.request.form['class']
    classification_reason = flask.request.form['reason']
    evaluated = "yes" if classification != "unclassified" else "no"
    urls_string = "('" + "', '".join(selected_urls) + "')"
    with SQLiteWrapper(config.db_path) as db:
        if note:
            db.execute(f"UPDATE urls SET note = ?, last_edit = ?, evaluated = ? WHERE url IN {urls_string}", (note, user, evaluated))
        if classification:
            db.execute(f"UPDATE urls SET classification = ?, last_edit = ?, evaluated = ? WHERE url IN {urls_string}", (classification, user, evaluated))
        if classification_reason:
            db.execute(f"UPDATE urls SET classification_reason = ?, last_edit = ?, evaluated = ? WHERE url IN {urls_string}", (classification_reason, user, evaluated))
        if classification == "malicious":
            for url in selected_urls:
                back_propagation(db, url)
    return redirect(url_for("list_all"))


@app.route('/api/url_stats', methods=['GET'])
def api_url_stats():
    try:
        url = flask.request.args.get('url')
    except BadRequestKeyError:
        return make_response(jsonify({'error': 'Not found'}), 404)
    with SQLiteWrapper(config.db_path) as db:
        url_detail = db.execute("SELECT url, first_seen, last_seen, hash, classification, classification_reason, note, reported, occurrences, vt_stats, evaluated, file_mime_type, content_size, threat_label FROM urls WHERE url = ? LIMIT 1;", (url,)).fetchall()
        url_sources = db.execute("SELECT source FROM url_source WHERE url = ?", (url,)).fetchall()
        if not url_detail:
            return make_response(jsonify({'error': 'Not found'}), 404)

    return_dict = {
        "url": url_detail[0][0],
        "first_seen": url_detail[0][1],
        "last_seen": url_detail[0][2],
        "hash": url_detail[0][3],
        "classification": url_detail[0][4],
        "classification_reason": url_detail[0][5],
        "note": url_detail[0][6],
        "reported": url_detail[0][7],
        "occurrences": url_detail[0][8],
        "vt_stats": url_detail[0][9],
        "evaluated": url_detail[0][10],
        "file_mime_type": url_detail[0][11],
        "content_size": url_detail[0][12],
        "threat_label": url_detail[0][13],
        "src": ", ".join(url_sources),
    }
    return make_response(jsonify(return_dict), 200)
