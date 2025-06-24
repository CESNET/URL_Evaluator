#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure cron ==============="

echob "** Copying cron config file **"

cp $BASEDIR/cron/url_evaluator /etc/cron.d/url_evaluator
