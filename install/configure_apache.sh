#!/bin/sh
# Configure Apache to serve evaluator web UI
# Pass base location without trailing slash (e.g. "/url_evaluator" or "/") as parameter
# (default is "/")

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure Apache ==============="

# (in case base_loc is server root, httpd needs "/", while evaluator needs "")
base_loc_httpd="/" # location without trailing slash (except when "/")
base_loc_httpd_slash="/" # location with trailing slash
base_loc_evaluator=""

# If base_loc is set and not root directory (which is default and treated specially)
if [ -n "$1" -a "$1" != "/" ] ; then
  base_loc_httpd="$1"
  base_loc_httpd_slash="$1/"
  base_loc_evaluator="$1"
fi

echob "Base location: $base_loc_httpd"
echob "** Installing Apache and WSGI **"
yum install -q -y httpd httpd-devel mod_wsgi
pip3 -q install mod_wsgi

# Add apache user to the url_evaluator group
usermod -aG url_evaluator apache

# Replace the stock mod_wsgi.so with the one from Python36
rm -f /usr/lib64/httpd/modules/mod_wsgi.so
path="$(pip3 show mod_wsgi 2>/dev/null | sed -n '/Location: / s/Location: //p')"
if [ -z "$path" ] ; then
  echor "ERROR: Can't find the path to mod_wsgi python package, can't create symlink to it. Apache won't start." >&2
else
  ln -s "$path"/mod_wsgi/server/mod_wsgi-py36.*.so /usr/lib64/httpd/modules/mod_wsgi.so
fi

echob "** Setting up configuration files **"
cp $BASEDIR/httpd/url_evaluator.conf /etc/httpd/conf.d/url_evaluator.conf

# Set up base loc in both apache conf and URL Evaluator conf
sed -i -E "s|^Define\s+EvaluatorBaseLoc\s+.*$|Define EvaluatorBaseLoc $base_loc_httpd|" /etc/httpd/conf.d/url_evaluator.conf
sed -i -E "s|^Define\s+EvaluatorBaseLocS\s+.*$|Define EvaluatorBaseLocS $base_loc_httpd_slash|" /etc/httpd/conf.d/url_evaluator.conf
sed -i -E "s|^base_url:.*$|base_url: \"$base_loc_evaluator\"|" /etc/url_evaluator/config.yaml

# Set up random "secret" number for Flask
secret=$(head -c 24 /dev/urandom | base64)
sed -i -E "s|^flask_secret_key:.*$|flask_secret_key: \"$secret\"|" /etc/url_evaluator/config.yaml

echob "** Setting up firewall (allow port 80, 443) **"
iptables -I INPUT 1 -p TCP --dport 80 -j ACCEPT
iptables -I INPUT 1 -p TCP --dport 443 -j ACCEPT
iptables-save > /etc/sysconfig/iptables

echob "** Starting Apache **"
systemctl enable httpd
systemctl restart httpd
