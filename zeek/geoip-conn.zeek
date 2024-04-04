##! Populate geolocation fields in the connection logs.
##! This package includes GeoLite2 data created by MaxMind, available from
##! https://www.maxmind.com

module Conn;

# The following redef ensuers the .mmdb included with this package is used
# out-of-the-box. If you delete that file, Zeek will fall back to looking in
# default locations. See this link for paths:
#
# https://github.com/zeek/zeek/blob/09483619ef0839cad189f22c4d5be3d66cedcf55/src/zeek.bif#L3964-L3971

redef mmdb_dir = @DIR;

export {
	type GeoInfo: record {
		country_code: string &optional &log;
		region: string &optional &log;
		city: string &optional &log;
		latitude: double &optional &log;
		longitude: double &optional &log;
		as_number: count &optional &log;
		as_org: string &optional &log;
	};

	type GeoPair: record {
		orig: GeoInfo &optional &log;
		resp: GeoInfo &optional &log;
	};

	redef record Conn::Info += {
		geo: GeoPair &optional &log;
	};
}

event connection_state_remove(c: connection) 
	{
	local orig_geo: GeoInfo;
	local orig_loc = lookup_location(c$id$orig_h);
	if ( orig_loc?$country_code )
		orig_geo$country_code = orig_loc$country_code;
	if ( orig_loc?$region )
		orig_geo$region = orig_loc$region;
	if ( orig_loc?$city )
		orig_geo$city = orig_loc$city;
	if ( orig_loc?$latitude )
		orig_geo$latitude = orig_loc$latitude;
	if ( orig_loc?$longitude )
		orig_geo$longitude = orig_loc$longitude;
	local orig_as_info = lookup_autonomous_system(c$id$orig_h);
	if ( orig_as_info?$number )
		orig_geo$as_number = orig_as_info$number;
	if ( orig_as_info?$organization )
		orig_geo$as_org = orig_as_info$organization;

	local resp_geo: GeoInfo;
	local resp_loc = lookup_location(c$id$resp_h);
	if ( resp_loc?$country_code )
		resp_geo$country_code = resp_loc$country_code;
	if ( resp_loc?$region )
		resp_geo$region = resp_loc$region;
	if ( resp_loc?$city )
		resp_geo$city = resp_loc$city;
	if ( resp_loc?$latitude )
		resp_geo$latitude = resp_loc$latitude;
	if ( resp_loc?$longitude )
		resp_geo$longitude = resp_loc$longitude;
	local resp_as_info = lookup_autonomous_system(c$id$resp_h);
	if ( resp_as_info?$number )
		resp_geo$as_number = resp_as_info$number;
	if ( resp_as_info?$organization )
		resp_geo$as_org = resp_as_info$organization;

	local geo_pair: GeoPair;
	geo_pair$orig = orig_geo;
	geo_pair$resp = resp_geo;

	c$conn$geo = geo_pair;

	}
