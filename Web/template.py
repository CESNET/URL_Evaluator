import math
import re
import socket
import sqlite3
import flask
import validators
import requests
import yaml
import os

from datetime import datetime
from flask import Flask, jsonify, render_template, make_response, redirect, url_for
from werkzeug.exceptions import BadRequestKeyError
from pymisp import PyMISP, PyMISPError

config_path='/data/url_evaluator/Web/web_config.yaml'

class Config:
    def __init__(self) -> None:
        with open(config_path) as file:
            self.config = yaml.safe_load(file)
            self.db_path = self.config["db_path"]
            self.misp_url = self.config["misp_url"]
            self.misp_key = self.config["misp_key"]

class URLDetail:
    def __init__(self) -> None:
        self.url = ""
        self.first_seen = ""
        self.last_seen = ""
        self.src = ""
        self.hash = ""
        self.classification = ""
        self.reason = ""
        self.note = ""
        self.reported = ""
        self.occurrences = 0
        self.vt_stats = ""
        self.evaluated = ""
        self.mime = ""
        self.content_size = 0
        self.threat_label = ""
        self.status = ""
        self.last_active = ""
        self.last_edit = ""
        self.ip = ""



config = Config()
page = 1
filters = ""
filter_params = {}

application = app = Flask(__name__)

# Connect to the database and get select data
def list_from_db(sql_string: str):
    print(f"Connecting to database at {config.db_path}")
    conn_db = sqlite3.connect(config.db_path)
    cursor_db = conn_db.cursor()
    print(f"Executing SQL query: {sql_string}")
    cursor_db.execute(sql_string)
    database_list = cursor_db.fetchall()
    conn_db.close()
    return database_list

# Connect to the database and add data
def add_to_db(sql_string: str):
    conn_db = sqlite3.connect(config.db_path)
    cursor_db = conn_db.cursor()
    cursor_db.execute(sql_string)
    conn_db.commit()
    conn_db.close()

# get link for urlhaus
def get_urlhaus_link(url):
    # Construct the HTTP request
    data = {'url' : url}
    response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data)
    # Parse the response from the API
    json_response = response.json()
    if json_response['query_status'] == 'ok':
        return json_response['urlhaus_reference']
    else:
        return None

# get link for misp
def get_misp_link(url):
    # Configure your MISP instance's URL and API key
    misp_url = config.misp_url
    misp_key = config.misp_key
    misp_verifycert = False  # Set to True if your MISP instance has a valid SSL certificate

    # Initialize the PyMISP instance
    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    # Attribute details
    attribute_value = url  # Replace with the attribute value you're searching for
    attribute_type = 'url'  # Replace with the attribute type you're searching for

    # Search for events containing the specified attribute
    try:
        events = misp.search(controler="events", value=attribute_value, type_attribute=attribute_type)
        event_id = events[0]['Event']['id']
    except IndexError:
        return None
    return f"{misp_url}/events/view/{event_id}"


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


def parse_detail(url_detail):
    # f"SELECT url, first_seen, last_seen, hash, classification, classification_reason, note, reported, url_occurrences, vt_stats, evaluated, file_mime_type, content_size, threat_label, status, last_active, last_edit FROM urls WHERE url = '{url}' LIMIT 1"
    url = URLDetail()
    url.url = url_detail[0]
    url.first_seen = url_detail[1]
    url.last_seen = url_detail[2]
    url.hash = url_detail[3]
    url.classification = url_detail[4]
    url.reason = url_detail[5]
    url.note = url_detail[6]
    url.reported = url_detail[7]
    url.occurrences = url_detail[8]
    url.vt_stats = url_detail[9]
    url.evaluated = url_detail[10]
    url.file_mime_type = url_detail[11]
    url.content_size = url_detail[12]
    url.threat_label = url_detail[13]
    url.status = url_detail[14]
    url.last_active = url_detail[15]
    url.last_edit = url_detail[16]
    url.ip = get_ip(url.url)

    return url

def parse_sources(url_detail, sources):
    source_string = ""
    for source in sources:
        if source_string != "":
            source_string += ", " 
        source_string += source[0]
    
    url_detail.src = source_string

    return url_detail

def parse_filters():
    parsed_filters = " WHERE url NOT NULL"
    for param in filter_params.keys():
        if param == "order" or param == "order_key" or filter_params[param] == "":
            continue
        if param == "classification":
            parsed_filters = parsed_filters + f" AND classification='{filter_params[param]}'"
        if param == "url":
            parsed_filters = parsed_filters + f" AND url LIKE '%{filter_params[param]}%'"
        if param == "hash":
            parsed_filters = parsed_filters + f" AND hash LIKE '%{filter_params[param]}%'"
        if param == "note":
            parsed_filters = parsed_filters + f" AND note LIKE '%{filter_params[param]}%'"
        if param == "reason":
            parsed_filters = parsed_filters + f" AND classification_reason LIKE '%{filter_params[param]}%'"
        if param == "status":
            parsed_filters = parsed_filters + f" AND status='{filter_params[param]}'"
        if param == "src":
            parsed_filters = parsed_filters + f" AND url IN (SELECT url FROM url_source WHERE source = {filter_params[param]})"
        
    try:
        if filter_params["evaluated"] == "no":
            parsed_filters = parsed_filters + f" AND evaluated='{filter_params['evaluated']}'"
    except KeyError:
        parsed_filters = parsed_filters + f" AND evaluated='yes'"

    parsed_filters = parsed_filters + f" ORDER BY {filter_params['order_key']} {filter_params['order']}"

    return parsed_filters

def get_sources():
    select_sources = "SELECT id, source FROM sources"
    sources = list_from_db(select_sources)
    return sources
        

@app.route('/', methods=['GET', 'POST'])
def main():   
    # global variables
    global page
    global filter_params

    user = get_user(flask.request.environ)
    
    # variables for showing pages of table 
    rows_per_page = 25

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

    # set filter of the list
    if flask.request.method == 'POST':  
        try:  
            find_url = flask.request.form['find-url'].strip()
            if find_url:
                find_url = find_url.replace("'", "''")
            filter_params["url"] = find_url
        except BadRequestKeyError:
            pass

        try:
            find_hash = flask.request.form['find-hash'].strip()
            if find_hash:
                find_hash = find_hash.replace("'", "''")
            filter_params["hash"] = find_hash
        except BadRequestKeyError:
            pass

        try:
            find_note = flask.request.form['find-note'].strip()
            if find_note:
                find_note = find_note.replace("'", "''")
            filter_params["note"] = find_note
        except BadRequestKeyError:
            pass

        try:
            find_reason = flask.request.form['find-reason'].strip()
            if find_reason:
                find_reason = find_reason.replace("'", "''")
            filter_params["reason"] = find_reason
        except BadRequestKeyError:
            pass

        try:
            filter_class = flask.request.form['classification'].strip()
            filter_params["classification"] = filter_class
        except BadRequestKeyError:
            pass

        try:
            filter_status = flask.request.form['status'].strip()
            filter_params["status"] = filter_status
        except BadRequestKeyError:
            pass

        try:
            filter_src = flask.request.form['src'].strip()
            filter_params["src"] = filter_src
            print(filter_src)
        except BadRequestKeyError:
            pass

        # add new url
        try:
            add_url = flask.request.form['add-url'].strip()
            add_url = add_url.replace("'", "''")
            if add_url and validators.url(add_url):
                from_db = list_from_db("SELECT url, url_occurrences FROM urls WHERE url = '" + add_url + "'")
                if not from_db:
                    add_to_db("INSERT INTO urls (url, first_seen, last_seen, reported, url_occurrences, evaluated) VALUES ('" + add_url + "', '"+ datetime.now().strftime('%Y-%m-%d') +"', '" + datetime.now().strftime('%Y-%m-%d') + "', 'no', 1, 'no')")
                    adding = "success"
                else:
                    adding = "in_db"

                conn = sqlite3.connect(config.db_path)
                cur = conn.cursor()
                conn.execute("PRAGMA foreign_keys = ON;")
                cur.execute("SELECT id FROM sources WHERE source = 'manual'")
                source_id = cur.fetchone()
                if not source_id:
                    cur.execute("INSERT INTO sources (source) VALUES ('manual')")
                    conn.commit()
                    cur.execute("SELECT id FROM sources WHERE source = 'manual'")
                    source_id = cur.fetchone()
                source_id = source_id[0]
                cur.execute("INSERT INTO url_source (url, source) VALUES (?, ?)", (add_url, source_id))
                conn.commit()
                conn.close()
            else:
                adding = "fail"
        except BadRequestKeyError:
            pass
    

    show = flask.request.args.get('show')

    if show == "not_evaluated":
        filter_params["evaluated"] = "no"
    else:
        if show == "malicious":
            filter_params["classification"] = "malicious"
        elif show == "unclassified":
            filter_params["classification"] = "unclassified"

    # set order of the list
    order = flask.request.args.get('order')
    if not order:
        order = "desc"
    key = flask.request.args.get('key')
    if not key:
        key = "last"
    if key == "url":
        order_key = "url"
    elif key == "first":
        order_key = "first_seen"
    elif key == "last":
        order_key = "last_seen"
    elif key == "occ":
        order_key = "url_occurrences"
    elif key == "class":
        order_key = "classification"
    elif key == "reason":
        order_key = "classification_reason"
    else:
        order_key = "last_seen"

    filter_params["order"] = order
    filter_params["order_key"] = order_key

    filters = parse_filters()

    select_rows = "SELECT url, first_seen, last_seen, url_occurrences, classification, classification_reason, note, status FROM urls"
    select_rows = select_rows + filters
    select_rows = select_rows + f" LIMIT {rows_per_page} OFFSET {rows_per_page * (page - 1)}"
    
    url_list = list_from_db(select_rows)

    # get number of pages
    select_sql = f"SELECT COUNT(*) FROM urls" + filters
    record_count = list_from_db(select_sql)[0][0]
    page_count = math.ceil(record_count / rows_per_page)

    # get sources for filters
    sources = get_sources()


    return render_template('list_all.html', user=user, url_list=url_list, order=order, key=key, show=show, adding=adding, sql=select_sql, page=page, page_count=page_count, filter_params=filter_params, sources=sources)


@app.route('/detail', methods=['GET', 'POST'])
def detail():
    user = get_user(flask.request.environ)
    show = flask.request.args.get('show')
    url = flask.request.args.get('url')
    if flask.request.method == 'POST':
        conn_db = sqlite3.connect(config.db_path)
        cursor_db = conn_db.cursor()
        cursor_db.execute("UPDATE urls SET evaluated = 'no' WHERE url = ?", (url,))
        conn_db.commit()
        conn_db.close()
    url = url.replace("'", "''")

    # get url details
    select_sql = f"SELECT url, first_seen, last_seen, hash, classification, classification_reason, note, reported, url_occurrences, vt_stats, evaluated, file_mime_type, content_size, threat_label, status, last_active, last_edit FROM urls WHERE url = '{url}' LIMIT 1"
    url_detail = list_from_db(select_sql)
    url_detail = parse_detail(url_detail[0])

    # get sources
    select_sources = f"SELECT sources.source FROM url_source JOIN sources ON url_source.source = sources.id WHERE url_source.url = '{url}'"
    sources = list_from_db(select_sources)
    url_detail = parse_sources(url_detail, sources)

    select_sessions = f"SELECT sessions.session, sessions.idea_id FROM sessions JOIN url_session ON url_session.session=sessions.session_hash WHERE url_session.url = '{url}'"
    sessions = list_from_db(select_sessions)

    # count not active days
    not_active = 0
    if url_detail.status == 'inactive':
        not_active = (datetime.now().date() - datetime.strptime(url_detail.last_active, '%Y-%m-%d').date()).days

    # get link for external sources
    if url_detail.reason is not None and "blacklist" in url_detail.reason.lower():
        link = get_urlhaus_link(url)
    elif url_detail.reason == "Hash control":
        link = f"https://www.virustotal.com/gui/file/{url_detail.hash}"
    else: 
        link = None

    # get link for misp if reported
    if url_detail.reported == "yes":
        try:
            link_misp = get_misp_link(url)
        except PyMISPError:
            link_misp = None
    else:
        link_misp = None

    # links for sandboxes
    links = {
        "misp": link_misp,
        "reason-link": link,
        "joe-sandbox": f"https://www.joesandbox.com/search?q={url_detail.hash}",
    }

    return render_template('detail.html', user=user, url=url_detail, sessions=sessions, show=show, links=links, link_misp=link_misp, not_active=not_active)


@app.route('/edit_detail', methods=['GET', 'POST'])
def edit_detail():
    user = get_user(flask.request.environ)
    url = flask.request.args.get('url')
    show = flask.request.args.get('show')
    conn_db = sqlite3.connect(config.db_path)
    cursor_db = conn_db.cursor()

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        classification = flask.request.form['class']
        classification_reason = flask.request.form['reason']
        cursor_db.execute("UPDATE urls SET note = ?, classification = ?, classification_reason = ?, last_edit = ? WHERE url = ?", (note, classification, classification_reason, user, url))
        conn_db.commit()
        return redirect(url_for("main", show=show))
    
    url = url.replace("'", "''")
    select_sql = f"SELECT * FROM urls WHERE url = '{url}' LIMIT 1"

    cursor_db.execute(select_sql)
    url_list = cursor_db.fetchall()

    conn_db.close()
    return render_template('edit_detail.html', user=user, url=url_list[0], show=show)

@app.route('/bulk_edit', methods=['GET', 'POST'])
def bulk_edit():
    user = get_user(flask.request.environ)
    print(flask.request.method)
    selected_urls = flask.request.form.getlist('selected_urls_list[]')
    print(selected_urls)
    
    return render_template('bulk_edit.html', selected_urls=selected_urls, user=user)

@app.route('/bulk_edit_action', methods=['POST'])
def bulk_edit_action():
    user = get_user(flask.request.environ)
    selected_urls = flask.request.form.getlist('selected_urls_list[]')
    print(selected_urls)
    conn_db = sqlite3.connect(config.db_path)
    cursor_db = conn_db.cursor()

    note = flask.request.form['note']
    classification = flask.request.form['class']
    classification_reason = flask.request.form['reason']
    print(note)
    print(classification)
    print(classification_reason)
    urls_string = "('" + "', '".join(selected_urls) + "')"
    print(urls_string)
    if note != "":
        cursor_db.execute(f"UPDATE urls SET note = ?, last_edit = ? WHERE url IN {urls_string}", (note, user))
        conn_db.commit()
    if classification != "":
        cursor_db.execute(f"UPDATE urls SET classification = ?, last_edit = ? WHERE url IN {urls_string}", (classification, user))
        conn_db.commit()
    if classification_reason != "":
        cursor_db.execute(f"UPDATE urls SET classification_reason = ?, last_edit = ? WHERE url IN {urls_string}", (classification_reason, user))
        conn_db.commit()
    # cursor_db.execute("UPDATE urls SET note = ?, classification = ?, classification_reason = ?, last_edit = ? WHERE url IN (" + ",".join("?" * len(selected_urls)) + ")", (note, classification, classification_reason, user, *selected_urls))
    # conn_db.commit()
    return redirect(url_for("main"))

@app.route('/api/url_stats', methods=['GET'])
def api_url_stats():
    try:
        url = flask.request.args.get('url')
    except BadRequestKeyError:
        return make_response(jsonify({'error': 'Not found'}), 404)
    select_sql = f"SELECT url, first_seen, last_seen, src, hash, classification, classification_reason, note, reported, url_occurrences, vt_stats, evaluated, file_mime_type, content_size, threat_label FROM urls WHERE url = '{url}' LIMIT 1;"
    url_detail = list_from_db(select_sql)
    if not url_detail:
        return make_response(jsonify({'error': 'Not found'}), 404)
    conn = sqlite3.connect(config.db_path)
    cur = conn.cursor()
    conn.execute("PRAGMA foreign_keys = ON;")
    cur.execute("SELECT sources.source FROM url_source JOIN sources ON url_source.source = sources.id WHERE url_source.url = ?", (url,))
    sources = cur.fetchall()
    conn.close()
    src = ""
    for source in sources:
        if src != "":
            src += ", "
        src += source[0]

    return_dict = {
        "url": url_detail[0][0],
        "first_seen": url_detail[0][1],
        "last_seen": url_detail[0][2],
        "src": src,
        "hash": url_detail[0][4],
        "classification": url_detail[0][5],
        "classification_reason": url_detail[0][6],
        "note": url_detail[0][7],
        "reported": url_detail[0][8],
        "url_occurrences": url_detail[0][9],
        "vt_stats": url_detail[0][10],
        "evaluated": url_detail[0][11],
        "file_mime_type": url_detail[0][12],
        "content_size": url_detail[0][13],
        "threat_label": url_detail[0][14]
    }
    return make_response(jsonify(return_dict), 200)