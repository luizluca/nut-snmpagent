#!/bin/bash

./nuttable2snmp -v TABLE=device -v ID=4 < device.txt; echo
./nuttable2snmp -v TABLE=ups -v INDEX=device < ups.txt; echo
./nuttable2snmp -v TABLE=input -v INDEX=device < input.txt; echo
./nuttable2snmp -v TABLE=output -v INDEX=device < output.txt; echo
./nuttable2snmp -v TABLE=battery -v INDEX=device< battery.txt; echo
./nuttable2snmp -v TABLE=ambient -v INDEX=device< ambient.txt; echo
./nuttable2snmp -v TABLE=outlet -v INDEX=device< outlet.txt; echo
./nuttable2snmp -v TABLE=driver -v INDEX=device< driver.txt; echo
./nuttable2snmp -v TABLE=server -v INDEX=device< server.txt; echo
