# kraken 
A network sniffer which looks up WHOIS and Autonomous System number information about public IP addresses that it observes.

Run it with: sudo python kraken.py

It will create a SQLite db (kraken.db) where it will store the metadata around the IP addresses it observes.

It will create a log file (kraken.log) with details of what it's doing.

It will sniff on eth0.

(c) phreaklets
