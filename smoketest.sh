#!/bin/bash -x

apt-get update
apt-get install libmaxminddb-dev

# Install latest binary Zeek (as described below https://zeek.org/get-zeek/)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security:zeek.gpg > /dev/null
apt update
apt install zeek

# Add Zeek Package Manager and current revision of the geoip-conn package
pip install zkg
export PATH="/opt/zeek/bin:$PATH"
zkg autoconfig
zkg install --force geoip-conn --version "$PACKAGE_SHA"
find /opt/zeek/share/zeek/site
echo '@load packages' | tee -a /opt/zeek/share/zeek/site/local.zeek

# Do a lookup of an IP that's known to have a stable location.
zeek -e "print lookup_location(199.83.220.115);" local
