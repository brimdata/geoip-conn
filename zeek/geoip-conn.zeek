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
	redef record Conn::Info += {
		orig_country_code: string &optional &log;
		orig_region: string &optional &log;
		orig_city: string &optional &log;
		orig_latitude: double &optional &log;
		orig_longitude: double &optional &log;
		resp_country_code: string &optional &log;
		resp_region: string &optional &log;
		resp_city: string &optional &log;
		resp_latitude: double &optional &log;
		resp_longitude: double &optional &log;
	};
}

event connection_state_remove(c: connection) 
	{
	local orig_loc = lookup_location(c$id$orig_h);
	if ( orig_loc?$country_code )
		c$conn$orig_country_code = orig_loc$country_code;
	if ( orig_loc?$region )
		c$conn$orig_region = orig_loc$region;
	if ( orig_loc?$city )
		c$conn$orig_city = orig_loc$city;
	if ( orig_loc?$latitude )
		c$conn$orig_latitude = orig_loc$latitude;
	if ( orig_loc?$longitude )
		c$conn$orig_longitude = orig_loc$longitude;

	local resp_loc = lookup_location(c$id$resp_h);
	if ( resp_loc?$country_code )
		c$conn$resp_country_code = resp_loc$country_code;
	if ( resp_loc?$region )
		c$conn$resp_region = resp_loc$region;
	if ( resp_loc?$city )
		c$conn$resp_city = resp_loc$city;
	if ( resp_loc?$latitude )
		c$conn$resp_latitude = resp_loc$latitude;
	if ( resp_loc?$longitude )
		c$conn$resp_longitude = resp_loc$longitude;

	}

