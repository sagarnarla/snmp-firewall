snmp-firewall
=============

An SNMP version-1 firewall. Builds upon the net-snmp package with a deployable SNMP firewall.

Firewall.c is the monolith that contains all the code of the firewall except the SNMP parser which comes from the Net-SNMP
package.

FIREWALL Architecture

The is structures in to two sections. 
A reader thread that takes in requestes from the incoming SNMP ports. This thread is responsible for queuing and buffering
requests. 

A processing thread that gets created for every request that is received. The processing thread does the bulk of the
parsing and applying the filtering rules. The rules, structure and general background information has been detailed in the 
PDF Report.

The Workspace folder contains utlities I created to test the firewall.
