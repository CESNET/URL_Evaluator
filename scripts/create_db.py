#!/usr/bin/env python3

import os
import sys
import yaml
import sqlite3
from sqlite3 import Error

# Get path for database from config file
with open('./Config/config.yaml') as file:
    db_path = yaml.load(file, Loader=yaml.FullLoader)["db_path"]

# Check if file with given name already exists
if os.path.isfile(db_path):
    print(f"File with path and name {db_path} already exists.")
    while True:
        answer = input("Do you want to rewrite this file (your data will be lost)? (yes/no): ") 
        if answer.lower() in ["yes", 'y']:
            print("Rewriting file...")
            os.remove(db_path)
            break
        elif answer.lower() in ["no", 'n']:
            print("Could not create database.")
            sys.exit()
        else:
            print("Give valid answer.")
        

# Create database connection
print("Creating database...")
try:
    conn = sqlite3.connect(db_path)
except Error as e:
    print(e, file=sys.stderr)
    sys.exit(1)

# Create a cursor
cursor = conn.cursor()

print("Creating table...")

# Create table for URLs
cursor.execute("""
        CREATE TABLE urls (
        url text PRIMARY KEY,
        first_seen date,
        last_seen date,
        src text,
        hash text,
        classification text CHECK( classification IN ('malicious','harmless','unreachable','unclassified', 'invalid') ),
        classification_reason text,
        note text,
        reported text CHECK( reported IN ('yes','no')),
        url_occurrences integer,
        vt_stats text,
        evaluated text CHECK( evaluated IN ('yes','no')),
        file_mime_type text,
        content_size integer,
        threat_label text,
        status text,
        last_active date
        )
    """)
conn.commit()

print("Creating table 'sessions'...")
cursor.execute("""
        CREATE TABLE sessions (
        session_hash text PRIMARY KEY,
        session text
        )
    """)

conn.commit()

print("Creation table for relations between urls and sessions...")
cursor.execute("""
        CREATE TABLE url_session (
        id integer PRIMARY KEY AUTOINCREMENT,
        url text,
        session text,
        FOREIGN KEY (url) REFERENCES urls (url),
        FOREIGN KEY (session) REFERENCES sessions (session_hash)
        )
    """)
conn.commit()

conn.close()
print("Database was created")
