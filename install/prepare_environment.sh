
#!/bin/sh
# Creates a system user and various directories

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Preparing environment =============="
echob "** Creating user 'url_evaluator' **"
groupadd url_evaluator
useradd --system --home-dir /url_evaluator --shell /sbin/nologin -g url_evaluator url_evaluator

# Note: "chown" and "chown" use -R flag for a case there already is something
# in the directories from a previous installation.

echob "** Creating directories and setting up permissions **"
# Code base (executables, scripts, etc.)
mkdir -p /url_evaluator
chown -R url_evaluator:url_evaluator /url_evaluator/
chmod -R 775 /url_evaluator

# Configuration directory
mkdir -p /etc/url_evaluator
chown -R url_evaluator:url_evaluator /etc/url_evaluator/
chmod -R 775 /etc/url_evaluator

# Log directory
mkdir -p /var/log/url_evaluator
chown -R url_evaluator:url_evaluator /var/log/url_evaluator/
chmod -R 775 /var/log/url_evaluator

# Data directory
mkdir -p /data/url_evaluator
chown -R url_evaluator:url_evaluator /data/url_evaluator/
chmod -R 775 /data/url_evaluator
