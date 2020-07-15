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
		orig_country_code: string &optional;
		orig_region: string &optional;
		orig_city: string &optional;
		orig_latitude: double &optional;
		orig_longitude: double &optional;
		resp_country_code: string &optional;
		resp_region: string &optional;
		resp_city: string &optional;
		resp_latitude: double &optional;
		resp_longitude: double &optional;
	};

	redef record Conn::Info += {
		geo: GeoInfo &optional &log;
	};
}

event connection_state_remove(c: connection) 
	{
	local geodata: GeoInfo;

	local orig_loc = lookup_location(c$id$orig_h);
	if ( orig_loc?$country_code )
		geodata$orig_country_code = orig_loc$country_code;
	if ( orig_loc?$region )
		geodata$orig_region = orig_loc$region;
	if ( orig_loc?$city )
		geodata$orig_city = orig_loc$city;
	if ( orig_loc?$latitude )
		geodata$orig_latitude = orig_loc$latitude;
	if ( orig_loc?$longitude )
		geodata$orig_longitude = orig_loc$longitude;

	local resp_loc = lookup_location(c$id$resp_h);
	if ( resp_loc?$country_code )
		geodata$resp_country_code = resp_loc$country_code;
	if ( resp_loc?$region )
		geodata$resp_region = resp_loc$region;
	if ( resp_loc?$city )
		geodata$resp_city = resp_loc$city;
	if ( resp_loc?$latitude )
		geodata$resp_latitude = resp_loc$latitude;
	if ( resp_loc?$longitude )
		geodata$resp_longitude = resp_loc$longitude;

	c$conn$geo = geodata;
	}

