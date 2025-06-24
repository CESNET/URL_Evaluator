#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure Supervisor ==============="

echob "** Copying supervisor config files **"

# Copy main configuration file
cp $BASEDIR/supervisord.conf /etc/url_evaluator/supervisord.conf

# Copy files specifying individual components running under Supervisor
mkdir -p /etc/url_evaluator/supervisord.conf.d/
cp $BASEDIR/supervisord.conf.d/* /etc/url_evaluator/supervisord.conf.d/

chown -R url_evaluator:url_evaluator /etc/url_evaluator/supervisord.conf
chown -R url_evaluator:url_evaluator /etc/url_evaluator/supervisord.conf.d/

echob "** Create evaluatorctl script **"
echob "'evaluatorctl' is an alias for 'supervisorctl' with Evaluator configuration file"

echo '#!/bin/sh
supervisorctl -c /etc/url_evaluator/supervisord.conf $@' >/usr/bin/evaluatorctl
chmod +x /usr/bin/evaluatorctl

echob "** Set up supervisord systemd unit **"

cp $BASEDIR/url-evaluator-supervisor.service /etc/systemd/system/url-evaluator-supervisor.service
systemctl daemon-reload
#systemctl enable url-evaluator-supervisor
#systemctl restart url-evaluator-supervisor

echoy "** TO RUN URL EVALUATOR, START ITS SUPERVISOR: systemctl start url-evaluator-supervisor"
