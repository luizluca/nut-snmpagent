nut-snmpagent
=============

SNMP wrapper in order to expose the upsc output into Net-SNMP

This is a script wrapper that translate the output of upsc 
comand into a SNMP agent (pass_persist). This code use 
The NUT.mib, converted into xml with (smidump -f xml) and
a lot of metaprogramming to do the job.

How to use:

 /etc/snmp/snmpd.conf
 pass_persist .1.3.6.1.4.1.26376.99 /my/path/to/snmp-static.nut


