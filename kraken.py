# Kraken network sniffer (c) 2014 phreaklets

import logging
import logging.handlers as handlers
# turn off those irritating IPv6 warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from contextlib import contextmanager
from threading import Thread
from Queue import Queue, Empty
from scapy.all import IP,TCP,sniff #Import needed modules from scapy
import sys
import sqlite3
import datetime
import dns.resolver
from dns import reversename
from netaddr import IPAddress
import netaddr
import requests 
import os
import time

m_iface = "eth0"
m_finished = False
conn = 0

class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Handler for logging to a set of files, which switches from one file
    to the next when the current file reaches a certain size, or at certain
    timed intervals
    """
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        # If rotation/rollover is wanted, it doesn't make sense to use another
        # mode. If for example 'w' were specified, then if there were multiple
        # runs of the calling application, the logs from previous runs would be
        # lost if the 'w' is respected, because the log file would be truncated
        # on each run.
        if maxBytes > 0:
            mode = 'a'
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.

        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        """
        if self.stream is None:                 # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:                   # are we rolling over?
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)  #due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0

# logging
def log_setup(log_file=None):
    formatter = logging.Formatter(
        '%(asctime)s kraken [%(process)d]: %(message)s',
        '%b %d %H:%M:%S')
    formatter.converter = time.gmtime  # if you want UTC time
    logger = logging.getLogger()
    if log_file:
        log_handler=SizedTimedRotatingFileHandler(
            log_file, maxBytes=52428800, backupCount=5,
            when='s',interval=86400,
            #encoding='bz2',  # uncomment for bz2 compression
            )
    else:
        log_handler=logging.StreamHandler(sys.stdout)

    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

class DbConnector:
    conn = None

    @contextmanager
    def get_cursor(self):
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        finally:
            cursor.close()

    def initDB(self, name):
        # Create tables if db doesn't exist
        logging.debug("Initializing DB: %s" % name)
        try:
            with self.get_cursor() as cur:
                cur.execute('''CREATE TABLE kraken(ip text, hostname text, srcport integer, dstport integer, asnumber integer, ttl text, netrange text, netname text, descr text, country text, timefirstseen text)''')
        except sqlite3.Error, e:
            logging.debug("initDB failed: %s" % e)
            
    def __init__(self, dbname):
        logging.debug("Connecting to DB %s" % dbname)
        if (self.conn is None):
            try:
                if not os.path.isfile(dbname):
                    logging.debug("DB does not exist")
                    self.conn = sqlite3.connect(dbname)
                    self.initDB(dbname)
                else:
                    logging.debug("DB already exists")
                    self.conn = sqlite3.connect(dbname)
            except sqlite3.Error, e:
                logging.error("DB connection failed: %s" % e)

    def isipaddrindb(self, ipaddress):
        try:
            with self.get_cursor() as cur:
                cur.execute("select ip from kraken where ip=:ipaddr", {"ipaddr":str(ipaddress)})
                row = cur.fetchone()

                if row is not None:
                    logging.debug("IP address %s is in the database" % ipaddress)
                    return True
                else:
                    logging.debug("IP address %s is not in the database" % ipaddress)
                    return False
        except sqlite3.Error, e:
            logging.debug("isipaddrindb failed: %s" % e)

    def addipaddr(self, ipaddress, sport, dport):
        with self.get_cursor() as cur:
            cur.execute("INSERT INTO kraken VALUES (?,?,?,?,?,?,?,?,?,?,?)", (str(ipaddress),"",sport,dport,"","","","","","",datetime.datetime.now()))

    def addttl(self, ipaddress, ttl):
        with self.get_cursor() as cur:
            cur.execute("UPDATE kraken SET ttl=? WHERE ip=?", (str(ttl), str(ipaddress)))

    def addhostname(self, hostname, ipaddress):
        with self.get_cursor() as cur:
            cur.execute("UPDATE kraken SET hostname=? WHERE ip=?", (str(hostname), str(ipaddress)))

    def addwhois(self, netrange, country, descr, netname, ipaddr):
        logging.debug("network range = %s" % netrange)
        logging.debug("country = %s" % country)
        logging.debug("descr = %s" % descr)
        logging.debug("netname = %s" % netname)

        with self.get_cursor() as cur:
            cur.execute("UPDATE kraken SET netrange=?, country=?, descr=?, netname=? WHERE ip=?", (str(netrange), str(country), str(descr), str(netname), str(ipaddr)))

    def addas(self, asnumber, ipaddr):
        logging.debug("Adding AS to DB")
        logging.debug("AS number: %s" % asnumber)
        with self.get_cursor() as cur:
            cur.execute("UPDATE kraken SET asnumber=? WHERE ip=?", (int(asnumber), str(ipaddr)))

    def close_conn(self):
        self.conn.close()


def aslookup(dbconn, ipaddr):
    logging.debug("Looking up AS number for %s" % ipaddr)
    sep = ".in-addr.arpa"
    naaddr = netaddr.IPAddress(ipaddr).reverse_dns
    revipsrc = naaddr.split(sep,1)[0]
    asnquery = revipsrc + '.origin.asn.cymru.com'
  
    try:
        answers = dns.resolver.query(asnquery, 'TXT')
        strasnanswer = answers.response.answer[0].items[0].strings[0]
        asn = strasnanswer.partition(' ')[0]
        dbconn.addas(asn, ipaddr)
    except:
        logging.warning("AS lookup failed for %s" % ipaddr)
        pass

def whoislookup(dbconn, ipaddr):
    logging.debug("Looking up WHOIS information for %s" % ipaddr)
    riperesponse = ripelookup(ipaddr)
    if not riperesponse:
        arinresponse = arinlookup(ipaddr)
        if not arinresponse:
            logging.debug("No WHOIS results found for IP address: %s" % ipaddr)
        else:
            dbconn.addwhois(arinresponse[0], arinresponse[1], arinresponse[2], arinresponse[3], ipaddr)
    else:
        dbconn.addwhois(riperesponse[0], riperesponse[1], riperesponse[2], riperesponse[3], ipaddr)

def arinlookup(ipaddr):
    max_tries = 3
    url = "http://whois.arin.net/rest/ip/%s/pft" % ipaddr
    jsondata = ''

    logging.debug("Starting ARIN lookup for IP address: %s" % ipaddr)

    for n in range(max_tries):
        try:
            headers = {'Accept': 'application/json'}
            response = requests.get(url, headers=headers)
            jsondata = response.json()
        except requests.exceptions.RequestException or requests.exceptions.ConnectionError:
            if n == max_tries - 1:
                raise
                time.sleep(30)
        except requests.exceptions.HTTPError, e:
            logging.debug("Error connecting to ARIN: %s" % e)
            pass
        except requests.exceptions.ConnectionError, e:
            logging.debug("Error connecting to ARIN: %s" % e)
            pass
    try:
        netname = jsondata['ns4:pft']['net']['orgRef']['@name']
        descr = jsondata['ns4:pft']['net']['name']['$']
        country = jsondata['ns4:pft']['org']['iso3166-1']['code3']['$']

        if isinstance(jsondata['ns4:pft']['net']['netBlocks']['netBlock'],list):
            netrange = netaddr.IPRange(jsondata['ns4:pft']['net']['netBlocks']['netBlock'][0]['startAddress']['$'].partition(' - ')[0],jsondata['ns4:pft']['net']['netBlocks']['netBlock'][0]['endAddress']['$'].partition(' - ')[0])
        else:
            netrange = netaddr.IPRange(jsondata['ns4:pft']['net']['netBlocks']['netBlock']['startAddress']['$'].partition(' - ')[0],jsondata['ns4:pft']['net']['netBlocks']['netBlock']['endAddress']['$'].partition(' - ')[0])
        return ([netrange, country, descr, netname])
    except KeyError, e:
        logging.warning("ARIN key error for %s" % ipaddr)

def ripelookup(ipaddr):
    typefilter = "inetnum"
    source = "ripe"

    logging.debug("Starting RIPE lookup for IP address: %s" % ipaddr)
    if (IPAddress(ipaddr).is_unicast()):
        try:
            payload = { "type-filter" : typefilter, "source" : source, "query-string" : ipaddr }
            url = "http://rest.db.ripe.net/search"
            headers={"Accept" : "application/json"}
            response = requests.get(url, params=payload, headers=headers)
            jsonresult = response.json() 
            attributelist = jsonresult['objects']['object'][0]['attributes']['attribute']
            for i in attributelist:
                if i['name'] == "netname":
                    netname = i['value']
                    if netname == "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK":                    
                        return []
                elif i['name'] == "country":
                    country = i['value']
                elif i['name'] == "descr":
                    descr = i['value']
                elif i['name'] == "inetnum":
                    netrange = netaddr.IPRange(i['value'].partition(' - ')[0],i['value'].partition(' - ')[2])
        except requests.exceptions.ConnectionError:
            logging.error("RIPE Connection Error")
    return([netrange, country, descr, netname])

def ptrlookup(dbconn, ip):
    # setup resolver using Google's DNS server
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8']
    dnsname = ""

    try:
        dnsaddr = reversename.from_address(ip)
        dnsname = str(my_resolver.query(dnsaddr,"PTR")[0])
    except:
        dnsname = "NXDOMAIN"
        pass
    if dnsname is not "NXDOMAIN":
        dbconn.addhostname(dnsname[:-1], ip)
    else:
        dbconn.addhostname(dnsname, ip)

def getttl(dbconn, ttl, ip):
    # Get TTL
    if ttl < 64 and ttl > 49:
        logging.debug("pkt most likely from Linux-based system")
        dbconn.addttl(ip, "Linux")
    elif ttl < 128 and ttl > 113:
        logging.debug("pkt most likely from Windows-based system")
        dbconn.addttl(ip, "Windows")

def threaded_sniff_target(q):
    global m_finished
    sniff(iface = m_iface, count = 0, filter = "tcp and port 502 or port 21 or port 80 or port 23 or port 102 and not port 22 and not host 193.0.6.142 and not host 91.189.91.14", prn = lambda x : q.put(x))
    m_finished = True

def threaded_sniff():
    q = Queue()
    sniffer = Thread(target = threaded_sniff_target, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)

    dbconn = DbConnector("kraken.db")

    while True:
        try:
            pkt = q.get(timeout = 1)
            if pkt.haslayer(TCP):
                logging.debug('Handling IP address: %s' % pkt.getlayer(IP).src)
                ipsrc = pkt.getlayer(IP).src
                sport = pkt.getlayer(TCP).sport
                dport = pkt.getlayer(TCP).dport
                # Check if src IP addr is RFC1918
                if (IPAddress(ipsrc).is_private()):
                    logging.debug("IP packet has a RFC1918 src address, ignoring")
                elif (IPAddress(ipsrc).is_unicast()):
                    logging.debug("Processing IP packet from the public Internet")
                    if not dbconn.isipaddrindb(ipsrc):
                        logging.info("Looking up info on IP Address: %s" % ipsrc)
                        dbconn.addipaddr(ipsrc, sport, dport)

                        whoislookup(dbconn, ipsrc)

                        ptrlookup(dbconn, ipsrc)
            
                        aslookup(dbconn, ipsrc)
                
                        getttl(dbconn, pkt.getlayer(IP).ttl, ipsrc)
                    else:
                        logging.debug("IP address %s already in DB" % ipsrc)
            else:
                logging.debug("Non-TCPIP packet")
        except Empty:
            pass

def main():
    log_setup("kraken.log")
    logging.info("Sniffer starting...")
    threaded_sniff()

if __name__ == "__main__":
    main()
