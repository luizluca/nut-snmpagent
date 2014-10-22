#!/bin/sh

sed -e '
/require "snmppass"/{
	s/.*/#&/
	rsnmppass.rb
}
/require "cached_method"/ {
	s/.*/#&/
	rcached_method.rb
}' snmp.nut > snmp-static.nut

