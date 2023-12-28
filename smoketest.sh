#!/bin/bash -ex

# On a newly-opened PR, I've seen $GITHUB_SHA gets populated with a commit
# that can't actually be checked out. The Action passes us a value for the
# latest commit SHA for the source branch to cover that case, so use that
# instead when it's there.
if [ -z "$PULL_REQUEST_HEAD_SHA" ]; then
  PACKAGE_SHA="$GITHUB_SHA"
else
  PACKAGE_SHA="$PULL_REQUEST_HEAD_SHA"
fi

# Install the latest binary feature release build of Zeek per instructions at
# https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get -y install zeek python3-setuptools

# Add Zeek Package Manager and current revision of the geoip-conn package
pip3 install zkg wheel
export PATH="/opt/zeek/bin:$PATH"
zkg autoconfig
zkg install --force geoip-conn --version "$PACKAGE_SHA"
echo '@load packages' | tee -a /opt/zeek/share/zeek/site/local.zeek

# Do a lookup of an IP that's known to have a stable location.
zeek -e "print lookup_location(199.83.220.115);" local | grep "San Francisco"
