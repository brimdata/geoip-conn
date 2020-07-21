#!/bin/bash

# Steps to install latest binary Zeek as found below https://zeek.org/get-zeek/
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security:zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek

# Add Zeek Package Manager and current revision of the geoip-conn package
sudo pip install zkg
sudo zkg autoconfig
sudo zkg install --force geoip-conn --version "$PACKAGE_SHA"

# Do a lookup of an IP that's known to have a stable location.
sudo zeek -e "print lookup_location(8.8.8.8);" local
