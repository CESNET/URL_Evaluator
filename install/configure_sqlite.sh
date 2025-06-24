#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure sqlite ==============="

echob "** Setting up evaluator DB **"

sudo -u url_evaluator sqlite3 /data/url_evaluator/db.sqlite < $BASEDIR/create_db.sql
chmod 664 /data/url_evaluator/db.sqlite
