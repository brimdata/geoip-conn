# geoip-conn - Add geolocation fields to `conn` logs

## Summary

If you have Zeek compiled with
[GeoLocation support](https://docs.zeek.org/en/current/customizations.html#address-geolocation-and-as-lookups),
this package will add a nested record called `geo` to the `conn` log that
contains fields for each originating and responding IP that describe:

* Country code
* Region
* City
* Latitude
* Longitude
* Autonomous System Number
* Autonomous System Organization

A [GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/) geolocation
database is included with the package for out-of-the-box functionality.

## Attributions

This package includes GeoLite2 data created by MaxMind, available from
https://www.maxmind.com.

This package was inspired by an old Zeek script
[conn-add-geodata.bro](https://github.com/zeek/bro-scripts/blob/master/conn-add-geodata.bro)
which unfortunately lacks author or license information. Before creating this
package, a [thread on public Zeek Slack](https://zeekorg.slack.com/archives/CSZBXF6TH/p1594235715230000)
was initiated in an attempt to hunt down the author, but no definitive answer
was found. This package goes further by being delivered as a
[Zeek package](https://github.com/zeek/packages) and by adding fields for
more than just country info.

## About the included GeoLite2 database

Per [MaxMind documentation](https://support.maxmind.com/hc/en-us/articles/4407625342875-Upgrade-from-GeoLite2), the free
GeoLite2 database is less accurate than the paid GeoIP2
version. While the author of this package has not attempted it, the docs
indicate that the paid version should work as a "drop-in replacement".

The MaxMind docs also indicate the database is updated weekly, every Tuesday.
All attempts will be made to keep the database version in this repo current.
However, if you're concerned about accuracy, you may want to create your own
MaxMind login and keep your local copy up to date.

If you delete the database files `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` that come with this
package, Zeek will fall back to looking for databases in default locations. See
[zeek/zeek#3547](https://github.com/zeek/zeek/pull/3547) for details.
