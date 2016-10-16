# Cuttlefish colourized tshark/tcpdump (c) 2016 phreaklets
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
from pprint import pprint
from blessings import Terminal
#from scapy_ssl_tls.ssl_tls import TLS
from scapy.layers import http
from scapy.layers.ssl_tls import *

dbconn = None
m_iface = "eth1"
m_finished = False
conn = 0

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
        try:
            with self.get_cursor() as cur:
                cur.execute('''CREATE TABLE nautilus(srcip text, ethsrc text, dstip text, vendor text, srcport integer, dstport integer, ttl text, pof text, timefirstseen text, timelastseen text)''')
        except sqlite3.Error, e:
            print("initDB failed: %s" % e)

    def __init__(self, dbname):
        if (self.conn is None):
            try:
                if not os.path.isfile(dbname):
                    self.conn = sqlite3.connect(dbname)
                    self.initDB(dbname)
                else:
                    self.conn = sqlite3.connect(dbname)
            except sqlite3.Error, e:
                print("DB connection failed: %s" % e)

    def isipaddrindb(self, ipaddr):
        try:
            with self.get_cursor() as cur:
                cur.execute("select srcip from nautilus where srcip=:ipaddress", {"ipaddress":str(ipaddr)})
                row = cur.fetchone()

                if row is not None:
                    return True
                else:
                    return False
        except sqlite3.Error, e:
            print("isipaddrindb failed: %s" % e)

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

def getttl(ttl):
    # Get TTL
    if ttl == 64:
        return "Linux"
    elif ttl == 128:
        return "Windows"
    elif ttl == 254:
        return "Solaris"
    else:
        return None
    
def vendorlookup(ethsrc):
    vendor_eth = ethsrc.replace(":", "-")
    url = "http://api.macvendors.com/%s" % vendor_eth
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        if response is not None:
            return response.text
    except requests.exceptions.RequestException or requests.exceptions.ConnectionError:
        print("Requests error occured")
    return None

def threaded_sniff_target(q):
    global m_finished
    sniff(iface = m_iface, count = 0, store = 0, filter = "tcp", prn = lambda x : q.put(x))
    m_finished = True

def threaded_sniff():
    q = Queue()
    sniffer = Thread(target = threaded_sniff_target, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    time.sleep(1)
    t = Terminal()
    
    while True:
        try:
            pkt = q.get(timeout = 1)
            if pkt.haslayer(TCP):
                ethsrc = pkt.getlayer(Ether).src
                ethdst = pkt.getlayer(Ether).dst
                ipsrc = pkt.getlayer(IP).src
                ipdst = pkt.getlayer(IP).dst
                ttl = pkt.getlayer(IP).ttl
                sport = pkt.getlayer(TCP).sport
                dport = pkt.getlayer(TCP).dport

                if not dbconn.isipaddrindb(ipsrc):
                    ret_ttl = getttl(ttl)
                    if ret_ttl  is None:
                        print "T", t.blue("%s" % datetime.datetime.now().strftime('%H:%M:%S')), "MAC src addr", t.cyan("%s" % ethsrc), "MAC dst addr", t.cyan("%s" % ethdst), "TTL", t.red("%d" % ttl), "IP src addr", t.green("%s" % ipsrc), "IP dst addr", t.green("%s" % ipdst), "TCP src port", t.yellow("%s" % sport), "TCP dst port",  t.yellow("%s" % dport)
                    else:
                        print "T", t.blue("%s" % datetime.datetime.now().strftime('%H:%M:%S')), "MAC src addr", t.cyan("%s" % ethsrc), "MAC dst addr", t.cyan("%s" % ethdst), "OS", t.red("%s" % ret_ttl), "IP src addr", t.green("%s" % ipsrc), "IP dst addr", t.green("%s" % ipdst), "TCP src port", t.yellow("%s" % sport), "TCP dst port",  t.yellow("%s" % dport)
                    if sport == 80 or dport == 80:
                        if pkt.haslayer(http.HTTPRequest):
                            http_pkt = pkt.getlayer(http.HTTPRequest)
                            print t.move_right, t.move_right, "HTTP Method", t.yellow("%s" % http_pkt.fields['Method']), "Host", t.cyan("%s" % http_pkt.fields['Host']), "Path", t.green("%s" % http_pkt.fields['Path']),"User-Agent", t.blue("%s" % http_pkt.fields['User-Agent'])
                        elif pkt.haslayer(http.HTTPResponse):
                            http_pkt = pkt.getlayer(http.HTTPResponse)
                            try:
                                print t.move_right, t.move_right, "HTTP Response from", t.green("%s" % http_pkt.fields['Server']), "Date", t.yellow("%s" % http_pkt.fields['Date'])
                            except:
                                pass

                    if pkt.haslayer(TLS):
                        tls_packet = pkt.getlayer(TLS)
                        tls_record = tls_packet.fields['records'][0]
                        tls_record_type = tls_packet.fields['records'][0].fields['content_type']
                        if tls_record_type == 0x17:
                            try:
                                tls_version = tls_record['TLS Record'].fields['version']
                                if tls_version == 0x303:
                                    print t.move_right, t.move_right, "Application Data from TLS version", t.yellow("v1.2")
                                if tls_version == 0x302:
                                    print t.move_right, t.move_right, "Application Data from TLS version", t.yellow("v1.1")
                                if tls_version == 0x301:
                                    print t.move_right, t.move_right, "Application Data from TLS version", t.yellow("v1.0")
                                if tls_version == 0x300:
                                    print t.move_right, t.move_right, "Application Data from SSL version", t.yellow("v3.0")
                            except:
                                pass
                        elif tls_record_type == 0x16:
                            for rec in tls_packet.fields['records']:
                                #print rec['TLS Handshake'].fields['type']
                                try:
                                    if rec['TLS Handshake'].fields['type'] == 1:
                                        #print rec['TLS Client Hello'].fields['version']
                                        tls_clienthello_version = tls_record['TLS Client Hello'].fields['version']
                                        if tls_clienthello_version == 0x303:
                                            print t.move_right, t.move_right, "Client Hello version", t.yellow("v1.2")
                                        elif tls_clienthello_version == 0x302:
                                            print t.move_right, t.move_right, "Client Hello version", t.yellow("v1.1")
                                        elif tls_clienthello_version == 0x301:
                                            print t.move_right, t.move_right, "Client Hello version", t.yellow("v1.0")
                                        elif tls_clienthello_version == 0x300:
                                            print t.move_right, t.move_right, "Client Hello version", t.yellow("v3.0")
                                    elif rec['TLS Handshake'].fields['type'] == 2:
                                        #print rec['TLS Server Hello'].fields['version']
                                        tls_serverhello_version = tls_record['TLS Server Hello'].fields['version']
                                        if tls_serverhello_version == 0x303:
                                            print t.move_right, t.move_right, "Server Hello version", t.yellow("v1.2")
                                        elif tls_serverhello_version == 0x302:
                                            print t.move_right, t.move_right, "Server Hello version", t.yellow("v1.1")
                                        elif tls_serverhello_version == 0x301:
                                            print t.move_right, t.move_right, "Server Hello version", t.yellow("v1.0")
                                        elif tls_serverhello_version == 0x300:
                                            print t.move_right, t.move_right, "Server Hello version", t.yellow("v3.0")
                                except:
                                    pass
                else:
                    dbconn.refreshtimestamp(ethsrc)
            else:
                pass
        except Empty:
            pass

def main(argv):
    global dbconn
    global m_iface

    dbconn = DbConnector("cuttlefish.db")
    if len(sys.argv) >= 2:
        try:
            opts, args = getopt.getopt(argv,"hi:",["interface="])
        except getopt.GetoptError:
            print('cuttlefish.py -i <interface>')
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print('cuttlefish.py -i <interface>')
                sys.exit()
            elif opt in ("-i", "--interface"):
                m_iface = arg
            else:
                print("Error in response")
                sys.exit()
    else:
        print("Wrong number of arguments!")
        sys.exit()

    print("Cuttlefish starting...")
    threaded_sniff()

if __name__ == "__main__":
    main(sys.argv[1:])

