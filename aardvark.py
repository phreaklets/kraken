import getopt
import datetime
import time
import sys
import requests
import simplejson
from netaddr import IPAddress
import logging
import logging.handlers as handlers
# turn off those irritating IPv6 warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from contextlib import contextmanager
import datetime
import sqlite3
import socket, struct, os, array
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU

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
        '%(asctime)s aardvark [%(process)d]: %(message)s',
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
                cur.execute('''CREATE TABLE aardvark(srcip text, ethsrc text, dstip text, vendor text, srcport integer, dstport integer, ttl text, pof text, timefirstseen text, timelastseen text)''')
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
                cur.execute("select srcip from aardvark where srcip=:ipaddress", {"ipaddress":str(ipaddr)})
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
            cur.execute("INSERT INTO aardvark VALUES (?,?,?,?,?,?,?,?,?,?)", (str(srcip), str(ethsrc), str(dstip), str(vendor), sport, dport, "", str(pof), datetime.datetime.now(), datetime.datetime.now()))

    def addttl(self, ipaddr, ttl):
        with self.get_cursor() as cur:
            cur.execute("UPDATE aardvark SET ttl=? WHERE srcip=?", (str(ttl), str(ipaddr)))

    def refreshtimestamp(self, ipaddr):
        with self.get_cursor() as cur:
            cur.execute("UPDATE aardvark SET timelastseen=? WHERE srcip=?", (datetime.datetime.now(), str(ipaddr)))

    def close_conn(self):
        self.conn.close()
 
class IPSniff:
    def __init__(self, interface_name, on_ip_incoming, on_ip_outgoing):
 
        self.interface_name = interface_name
        self.on_ip_incoming = on_ip_incoming
        self.on_ip_outgoing = on_ip_outgoing
 
        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))
 
    def __process_ipframe(self, pkt_type, ip_header, src_eth_addr, payload):
 
        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)
 
        version_ihl = fields[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4

        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]
 
        ttl = fields[5]

        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]
 
        t = iph_length
        tcp_header = payload[t:t+20]
 
        #now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
             
        src_port = tcph[0]
        dst_port = tcph[1]

        if pkt_type == socket.PACKET_OUTGOING:
            if self.on_ip_outgoing is not None:
                self.on_ip_outgoing(src_eth_addr, ip_src, ip_dst, src_port, dst_port, ttl, ip_frame)
 
        else:
            if self.on_ip_incoming is not None:
                self.on_ip_incoming(src_eth_addr, ip_src, ip_dst, src_port, dst_port, ttl, ip_frame)

    #Convert a string of 6 characters of ethernet address into a dash separated hex string
    def eth_addr (self, a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b
 
    def recv(self):
        while True:
 
            pkt, sa_ll = self.ins.recvfrom(MTU)
 
            if type == socket.PACKET_OUTGOING and self.on_ip_outgoing is None:
                continue
            elif self.on_ip_outgoing is None:
                continue
 
            if len(pkt) <= 0:
                break
 
            eth_header = struct.unpack("!6s6sH", pkt[0:14])
 
            dummy_eth_protocol = socket.ntohs(eth_header[2])
 
            if eth_header[2] != 0x800 :
                continue

            src_eth_addr = self.eth_addr(pkt[6:12])

            ip_header = pkt[14:34]
            payload = pkt[14:]
 
            self.__process_ipframe(sa_ll[2], ip_header, src_eth_addr, payload)
 
def getttl(dbconn, ttl, ip):
    # Get TTL
    if ttl < 64 and ttl > 49:
        logging.debug("pkt most likely from Linux-based system")
        dbconn.addttl(ip, "Linux")
    elif ttl < 128 and ttl > 113:
        logging.debug("pkt most likely from Windows-based system")
        dbconn.addttl(ip, "Windows")
    else:
        logging.debug("pkt does not match")
        dbconn.addttl(ip, "Unknown")

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

def test_incoming_callback(src_eth_addr, src, dst, src_port, dst_port, ttl, frame):
    ipsrc = socket.inet_ntoa(src)
    ipdst = socket.inet_ntoa(dst)
    if (IPAddress(ipsrc).is_private() and IPAddress(ipsrc).is_unicast()):
        logging.debug("Processing IP packet from the private internal range")
        if not dbconn.isipaddrindb(ipsrc):
            vendor = vendorlookup(src_eth_addr)
            logging.info("Looking up info on IP Address: %s MAC Address: %s Vendor: %s" % (ipsrc, src_eth_addr, vendor))

            dbconn.addhost(src_eth_addr, vendor, ipsrc, ipdst, src_port, dst_port, "")

            getttl(dbconn, ttl, ipsrc)
        else:
            logging.debug("IP address %s already in DB, refreshing timestamp" % ipsrc)
            dbconn.refreshtimestamp(src_eth_addr)
    else:
        logging.debug("Non-TCPIP packet")
    logging.debug("incoming - src_eth_addr=%s src=%s, dst=%s, frame len = %d"
        %(src_eth_addr, socket.inet_ntoa(src), socket.inet_ntoa(dst), len(frame)))
 
def test_outgoing_callback(src_eth_addr, src, dst, src_port, dst_port, ttl, frame):
    ipsrc = socket.inet_ntoa(src)
    ipdst = socket.inet_ntoa(dst)
    if (IPAddress(ipsrc).is_private() and IPAddress(ipsrc).is_unicast()):
        logging.debug("Processing IP packet from the private internal range")
        if not dbconn.isipaddrindb(ipsrc):
            vendor = vendorlookup(src_eth_addr)
            logging.info("Looking up info on IP Address: %s MAC Address: %s Vendor: %s" % (ipsrc, src_eth_addr, vendor))

            dbconn.addhost(src_eth_addr, vendor, ipsrc, ipdst, src_port, dst_port, "")

            getttl(dbconn, ttl, ipsrc)
        else:
            logging.debug("IP address %s already in DB, refreshing timestamp" % ipsrc)
            dbconn.refreshtimestamp(src_eth_addr)
    else:
        logging.debug("Non-TCPIP packet")
    logging.debug("outgoing - src_eth_addr=%s src=%s, dst=%s, frame len = %d"
        %(src_eth_addr, socket.inet_ntoa(src), socket.inet_ntoa(dst), len(frame)))

def main(argv):
    global dbconn
    iface = ""
    log_setup("aardvark.log")
    dbconn = DbConnector("aardvark.db") 

    if len(sys.argv) >= 2:
        try:
            opts, args = getopt.getopt(argv,"hi:",["interface="])
        except getopt.GetoptError:
            print('aardvark.py -i <interface>')
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print('aardvark.py -i <interface>')
                sys.exit()
            elif opt in ("-i", "--interface"):
                iface = arg
            else:
                print("Error in response")
                sys.exit()
    else:
        print("Wrong number of arguments!")
        sys.exit()

    ip_sniff = IPSniff(iface, test_incoming_callback, test_outgoing_callback)
    ip_sniff.recv()

if __name__ == "__main__":
    main(sys.argv[1:])
