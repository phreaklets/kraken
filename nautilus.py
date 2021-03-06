# Nautlis passive asset collector (c) 2016 phreaklets
# mini Kraken :-)
import logging
import logging.handlers as handlers
# turn off those irritating IPv6 warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from contextlib import contextmanager
from threading import Thread
from Queue import Queue, Empty
from scapy.all import load_module,Ether,IP,TCP,sniff #Import needed modules from scapy
import sys
import sqlite3
import datetime
from netaddr import IPAddress
import os
import time
import getopt
import requests
import simplejson
from pprint import pprint
#from scapy.layers import http

dbconn = None
m_iface = "eth1"
m_finished = False
conn = 0

class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Taken from here: http://www.blog.pythonlibrary.org/2014/02/11/python-how-to-create-rotating-logs/
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
        '%(asctime)s nautilus [%(process)d]: %(message)s',
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
                cur.execute('''CREATE TABLE nautilus(srcip text, ethsrc text, dstip text, vendor text, srcport integer, dstport integer, ttl text, pof text, timefirstseen text, timelastseen text)''')
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

    def isipaddrindb(self, ipaddr):
        try:
            with self.get_cursor() as cur:
                cur.execute("select srcip from nautilus where srcip=:ipaddress", {"ipaddress":str(ipaddr)})
                row = cur.fetchone()

                if row is not None:
                    logging.debug("IP source address %s is in the database" % ipaddr)
                    return True
                else:
                    logging.debug("IP source address %s is not in the database" % ipaddr)
                    return False
        except sqlite3.Error, e:
            logging.debug("isipaddrindb failed: %s" % e)

    def addhost(self, ethsrc, vendor, srcip, dstip, sport, dport, pof):
        with self.get_cursor() as cur:
            cur.execute("INSERT INTO nautilus VALUES (?,?,?,?,?,?,?,?,?,?)", (str(srcip), str(ethsrc), str(dstip), str(vendor), sport, dport, "", str(pof), datetime.datetime.now(), datetime.datetime.now()))

    def addttl(self, ipaddr, ttl):
        with self.get_cursor() as cur:
            cur.execute("UPDATE nautilus SET ttl=? WHERE srcip=?", (str(ttl), str(ipaddr)))

    def refreshtimestamp(self, ipaddr):
        with self.get_cursor() as cur:
            cur.execute("UPDATE nautilus SET timelastseen=? WHERE srcip=?", (datetime.datetime.now(), str(ipaddr)))

    def close_conn(self):
        self.conn.close()

def getttl(dbconn, ttl, ip, ethsrc):
    # Get TTL
    if ttl < 64 and ttl > 49:
        logging.debug("pkt most likely from Linux-based system")
        dbconn.addttl(ethsrc, "Linux")
    elif ttl < 128 and ttl > 113:
        logging.debug("pkt most likely from Windows-based system")
        dbconn.addttl(ethsrc, "Windows")

def vendorlookup(ethsrc):
    vendor_eth = ethsrc.replace(":", "-")
    url = "https://www.macvendorlookup.com/api/v2/%s" % vendor_eth
    jsondata = ""
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        if response is not None:
            try:
                jsondata = response.json()
            except simplejson.decoder.JSONDecodeError:
                pass
    except requests.exceptions.RequestException or requests.exceptions.ConnectionError:
        logging.error("Requests error occured")
    if jsondata:
        return jsondata[0]['company']
    else:
        return None

def threaded_sniff_target(q):
    global m_finished
    sniff(iface = m_iface, count = 0, store = 0, filter = "tcp", prn = lambda x : q.put(x))
    m_finished = True

def threaded_sniff():
    load_module("p0f")
    q = Queue()
    sniffer = Thread(target = threaded_sniff_target, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)

    while True:
        try:
            pkt = q.get(timeout = 1)
            if pkt.haslayer(TCP):
                logging.debug('Handling IP address: %s' % pkt.getlayer(IP).src)
                ethsrc = pkt.getlayer(Ether).src
                ipsrc = pkt.getlayer(IP).src
                ipdst = pkt.getlayer(IP).dst
                sport = pkt.getlayer(TCP).sport
                dport = pkt.getlayer(TCP).dport
                # Check if src IP addr is RFC1918 and is unicast
                if (IPAddress(ipsrc).is_private() and IPAddress(ipsrc).is_unicast()):
                    logging.debug("Processing IP packet from the private internal range")
                    if not dbconn.isipaddrindb(ipsrc):
                        vendor = vendorlookup(ethsrc)
                        logging.info("Looking up info on IP Address: %s MAC Address: %s Vendor: %s" % (ipsrc, ethsrc, vendor))

                        dbconn.addhost(ethsrc, vendor, ipsrc, ipdst, sport, dport, p0f(pkt))

                        getttl(dbconn, pkt.getlayer(IP).ttl, ipsrc, ethsrc)
                    else:
                        logging.debug("IP address %s already in DB, refreshing timestamp" % ipsrc)
                        dbconn.refreshtimestamp(ethsrc)
            else:
                logging.debug("Non-TCPIP packet")
        except Empty:
            pass

def main(argv):
    global dbconn
    global m_iface

    log_setup("nautilus.log")
    dbconn = DbConnector("nautilus.db")
    if len(sys.argv) >= 2:
        try:
            opts, args = getopt.getopt(argv,"hi:",["interface="])
        except getopt.GetoptError:
            print('nautilus.py -i <interface>')
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print('nautlius.py -i <interface>')
                sys.exit()
            elif opt in ("-i", "--interface"):
                m_iface = arg
            else:
                print("Error in response")
                sys.exit()
    else:
        print("Wrong number of arguments!")
        sys.exit()

    logging.info("Sniffer starting...")
    print("Sniffer starting...")
    threaded_sniff()

if __name__ == "__main__":
    main(sys.argv[1:])

