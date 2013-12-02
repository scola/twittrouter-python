#!/usr/bin/env python
#coding=utf-8

from __future__ import with_statement
import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from twfoller import check_friendship,get_oauth,setup_oauth
import cgi
import threading
import os
import time
import re
import logging

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
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

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
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))
                return

        if re.search(str(form['uname'].value.strip()), gettwfoller(),re.IGNORECASE):
        if check_friendship(TwitterID,str(form['uname'].value.strip(),auth=oauth):    
            logging.info("auth success %s" %form['uname'].value)
            with open("VERIFY_OK.html",'r') as f:
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

            if self.client_address[0] in blocklist:
                logging.info("unblock the ip,feel free to use the wifi")
                os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j DNAT  --to-destination 192.168.1.1:8888' %self.client_address[0])
                blocklist.remove(self.client_address[0])
                authlist.append(self.client_address[0])
        else:
            with open("VERIFY_FAILED.html",'r') as f:
                #self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID))
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

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

    with open('config.json', 'rb') as f:
        config = json.load(f)
    whitelist = config['whitelist'].split('|')
    blocklist = []
    authlist = []
    TwitterID = config['TwitterID']
    CONSUMER_KEY = config['CONSUMER_KEY']
    CONSUMER_SECRET = config['CONSUMER_SECRET']
    OAUTH_TOKEN = config['OAUTH_TOKEN']
    OAUTH_TOKEN_SECRET = config['OAUTH_TOKEN_SECRET']

    if len(sys.argv) > 1:
        TwitterID = sys.argv[1]
    if not (TwitterID and CONSUMER_KEY and CONSUMER_SECRET):
        logging.critical("please add TwitterID,CONSUMER_KEY and CONSUMER_SECRET into config.json file") 
        sys.exit(-1)
    if not (OAUTH_TOKEN and OAUTH_TOKEN_SECRET):
        OAUTH_TOKEN,OAUTH_TOKEN_SECRET = setup_oauth(CONSUMER_KEY,CONSUMER_SECRET)
        config['OAUTH_TOKEN'] = OAUTH_TOKEN 
        config['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET
        with open('config.json', 'wb') as f:
            json.dump(config,f)

    oauth = get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET)
    t = createThread(target = getarplist,args=tuple())
    serveraddr = ('', 8888)
    srvr = ThreadingHTTPServer(serveraddr, RequestHandler)
    srvr.serve_forever()
