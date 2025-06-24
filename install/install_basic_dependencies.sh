#!/bin/sh
# Install all packages needed to run NERD and run all the services

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Install basic dependencies ==============="

echob "** Installing basic RPM packages **"
#yum install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
yum install -y -q git wget curl python3 python3-devel python3-setuptools sqlite sqlite-devel

echob "** Installing Python packages **"
pip3 install -q -r $BASEDIR/pip_requirements.txt

echob "** Installing Supervisor **"
pip3 -q install "supervisor==4.*"
ln -s /usr/local/bin/supervisord /usr/bin/supervisord
ln -s /usr/local/bin/supervisorctl /usr/bin/supervisorctl

echob "** All main dependencies installed **"
