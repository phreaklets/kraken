# kraken 
A network sniffer which looks up WHOIS and Autonomous System number information about public IP addresses that it observes.

Run it with: sudo python kraken.py

It will create a SQLite db (kraken.db) where it will store the metadata around the IP addresses it observes.

It will create a log file (kraken.log) with details of what it's doing.

It will sniff on eth0. Based on the awesomeness that is scapy.

# nautilus
The mini-kraken! ;-) 

Actually, this tools is the flip-side of the Kraken. It passively sniffs the network and records all the private IP addresses that it sees. It stores the MAC address and source IP address of a packet along with the destionation IP address, source port, destination port, TTL (deciding if it's Linux or Windows), hostname (you'll need to add your own internal DNS resolver IP address for this to work), the timestamp of when the device was first observed and the continously refreshed timestamp of when the device was last seen.

Nautilus stores all this information in a SQLite3 database called "nautilus.db". It outputs a log to "nautilus.log".

Usage:

sudo python nautilus.py -i eth0

(c) phreaklets
