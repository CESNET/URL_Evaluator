#!/bin/sh

if [ $(id -u) != 0 ]; then
  echo "This script must be run as root!"
  exit 1
fi

echob () {
  tput setaf 4 # light blue
  tput bold
  echo "$@"
  tput sgr0
}

# print important notes in yellow color
echoy () {
  tput setaf 3 # yellow
  tput bold
  echo "$@"
  tput sgr0
}

# Disable SELinux
# TODO: learn how to properly configure everything with SELinux enabled
setenforce 0
sed -i --follow-symlinks -e 's/^SELINUX=.*$/SELINUX=disabled/' /etc/sysconfig/selinux

alias yum="yum --disableplugin=fastestmirror"

echob "=============== Installing git (needed to clone repository) ==============="
yum install -y -q git

echob "=============== Cloning repository ==============="
if ! [ -d /tmp/url_evaluator_install ]; then
  mkdir /tmp/url_evaluator_install
  git clone https://github.com/CESNET/URL_Evaluator.git /tmp/url_evaluator_install
  cd /tmp/url_evaluator_install
  git checkout main
else
  echoy "NOTICE: Using existing installation files in /tmp/url_evaluator_install/"
  cd /tmp/url_evaluator_install
fi
chmod +x /tmp/url_evaluator_install/install/*.sh

# Prepare environment (create "url_evaluator" user, create directories, etc.)
/tmp/url_evaluator_install/install/prepare_environment.sh

echob "=============== Copying files ==============="
sudo -u url_evaluator mkdir -p /url_evaluator/{bin,web,common,scripts,nemea}
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/bin/* /url_evaluator/bin
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/web/* /url_evaluator/web
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/common/* /url_evaluator/common
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/scripts/* /url_evaluator/scripts
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/nemea/* /url_evaluator/nemea
sudo -u url_evaluator cp -R /tmp/url_evaluator_install/etc/* /etc/url_evaluator
chmod -R g+w /url_evaluator/
chmod -R g+w /etc/url_evaluator/
chmod -R +x /url_evaluator/scripts/

# Install and configure all dependencies
/tmp/url_evaluator_install/install/install_basic_dependencies.sh
/tmp/url_evaluator_install/install/configure_sqlite.sh
/tmp/url_evaluator_install/install/configure_apache.sh /url_evaluator # install to /url_evaluator
/tmp/url_evaluator_install/install/configure_cron.sh
/tmp/url_evaluator_install/install/configure_supervisor.sh

echob "=============== Create testing user accounts ==============="
# Set password for local test user
htpasswd -bc /etc/url_evaluator/htpasswd test test
chown apache:url_evaluator /etc/url_evaluator/htpasswd
chmod 660 /etc/url_evaluator/htpasswd
echoy
echoy "************************************************************"
echoy "A user account for testing is available:"
echoy ""
echoy "* Unprivileged local account - username/password: test/test"
echoy ""

echoy "************************************************************"
echoy "Installation script completed."
echoy "What to do now:"
echoy " 1. See logs above for potential error messages"
echoy " 2. Review the main config file (/etc/url_evaluator/config.yaml) and edit as needed"
echoy " 3. Install and configure Warden client"
echoy " 4. Create a user for the web interface"
echoy "      sudo htpasswd -c -B -C 12 /etc/url_evaluator/htpasswd username"
echoy " 5. Run the supervisor"
echoy "      sudo systemctl start url-evaluator-supervisor"
echoy " 6. Manage backend via supervisord interface (evaluatorctl)"
echoy " 7. Check frontend at https://<server_address>/url_evaluator/"
