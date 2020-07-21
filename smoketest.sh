#!/bin/bash -x

# Alas, we must compile Zeek because I've found the binary distributions are
# not compiled with libmaxminddba.
apt-get update
apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libmaxminddb-dev
git clone --recursive https://github.com/zeek/zeek zeek-src
cd zeek-src
./configure --prefix=/usr/local/zeek
make -j$(nproc)
make -j$(nproc) install

# Add Zeek Package Manager and current revision of the geoip-conn package
pip install zkg
export PATH="/usr/local/zeek/bin:$PATH"
zkg autoconfig
zkg install --force geoip-conn --version "$PACKAGE_SHA"
find /usr/local/zeek/share/zeek/site
echo '@load packages' | tee -a /usr/local/zeek/share/zeek/site/local.zeek

# Do a lookup of an IP that's known to have a stable location.
zeek -e "print lookup_location(199.83.220.115);" local | grep "San Francisco"
