#!/usr/bin/env python
#coding=utf-8

from __future__ import with_statement
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from twfoller import gettwfoller
import cgi
import threading
import os
import time
import re
import logging

whitelist = ['00:00:00:00:00:00','d8:57:ef:33:86:93','00:04:23:97:20:26','04:46:65:53:00:0b']
authlist = []
blocklist = []

class RequestHandler(BaseHTTPRequestHandler,SimpleHTTPRequestHandler):
    def _writeheaders(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_HEAD(self):
        self._writeheaders()

    def do_GET(self):
        if '.ico' in self.path or '.png' in self.path:
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self._writeheaders()
            with open("BASEHTML.html",'r') as f:
                self.wfile.write(f.read())

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
            'CONTENT_TYPE':self.headers['Content-Type'],
            })
        self._writeheaders()
        if not re.match(r'^\w+$', form['uname'].value.strip()):
            logging.info("you input invalid username %s" %form['uname'].value)
            with open("VERIFY_FAILED.html",'r') as f:
                self.wfile.write(f.read())
                return

        if re.search(str(form['uname'].value.strip()), gettwfoller(),re.IGNORECASE):
            logging.info("auth success %s" %form['uname'].value)
            with open("VERIFY_OK.html",'r') as f:
                self.wfile.write(f.read())

            if self.client_address[0] in blocklist:
                logging.info("unblock the ip,feel free to use the wifi")
                os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j DNAT  --to-destination 192.168.1.1:8888' %self.client_address[0])
                blocklist.remove(self.client_address[0])
                authlist.append(self.client_address[0])
        else:
            with open("VERIFY_FAILED.html",'r') as f:
                self.wfile.write(f.read())

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def createThread(target,args):
    t = threading.Thread(target=target,args=args)
    t.setDaemon(1)
    t.start()
    return t

def getarplist():
    time.sleep(5)	
    while True:
        client = os.popen('arp -n').read().strip().split('\n')[1:]
        ip_mac = lambda s: re.findall(r'\d+\.\d+\.\d+\.\d+|\w+:\w+:\w+:\w+:\w+:\w+',s)
        ip_mac_list = map(ip_mac,client)
        logging.info('scan the arp list')
        for ipmac in ip_mac_list:
            if len(ipmac)==2 and (ipmac[1] in whitelist or ipmac[0] in authlist or ipmac[0] in blocklist):
                continue
            elif len(ipmac)==2:
                logging.info("the new client should be blocked.ip == %s,mac == %s" %(ipmac[0],ipmac[1]))
                blocklist.append(ipmac[0])
                os.system('iptables -t nat -I PREROUTING -s %s -p tcp --dport 80 -j DNAT  --to-destination 192.168.1.1:8888' %ipmac[0])

        time.sleep(10)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    os.chdir(os.path.dirname(__file__) or '.')
    t = createThread(target = getarplist,args=tuple())
    serveraddr = ('', 8888)
    srvr = ThreadingHTTPServer(serveraddr, RequestHandler)
    srvr.serve_forever()
