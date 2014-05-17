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
import Queue

class RequestHandler(BaseHTTPRequestHandler,SimpleHTTPRequestHandler):
    gen = None
    twitter_id = None
    def send_to_client(self,filename):
        with open(filename,'r') as f:
            self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

    def _writeheaders(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    def _write_redirect_headers(self,redirect_url):
        self.send_response(301)
        self.send_header('Location', redirect_url)
        self.end_headers()

    def do_HEAD(self):
        self._writeheaders()

    def do_GET(self):
        if '.ico' in self.path or '.png' in self.path:
            SimpleHTTPRequestHandler.do_GET(self)
        elif "&oauth_verifier=" in self.path:
            logging.info("get oauth_verifier=%s" %self.path.split('=')[-1])
            verifier_queue.put(self.path.split('=')[-1])
            OAUTH_TOKEN,OAUTH_TOKEN_SECRET = RequestHandler.gen.next()
            global TwitterID
            TwitterID = RequestHandler.twitter_id
            config["TwitterID"] = TwitterID
            new_auth = []
            new_auth["OAUTH_TOKEN"] = OAUTH_TOKEN
            new_auth["OAUTH_TOKEN_SECRET"] = OAUTH_TOKEN_SECRET
            config[TwitterID] = new_auth
            with open(pathconfig, 'wb') as f:
                json.dump(config,f)
            self._writeheaders()
            with open("config_done.html",'r') as f:
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))
        elif "/config" == self.path and self.client_address[0] == "127.0.0.1":
            self._writeheaders()
            if TwitterID == "twitrouter":
                self.send_to_client("config.html")
            else:
                self.send_to_client("config_done.html")
        else:
            self._writeheaders()
            with open("BASEHTML.html",'r') as f:
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            keep_blank_values=True,
            environ={'REQUEST_METHOD':'POST',
            'CONTENT_TYPE':self.headers['Content-Type'],
            })
        if self.client_address[0] == "127.0.0.1" and 'twitter_auth' in form.keys() and re.match(r'^\w+$', form['twitter_auth'].value.strip().replace('_','')):
            logging.info("auth input %s" %form['twitter_auth'].value)
            twitter_auth = form['twitter_auth'].value.strip()
            if twitter_auth in config.keys():
                global TwitterID
                TwitterID = twitter_auth
                OAUTH_TOKEN = config[twitter_auth]["OAUTH_TOKEN"]
                OAUTH_TOKEN_SECRET = config[twitter_auth]["OAUTH_TOKEN_SECRET"]

                self._writeheaders()
                self.send_to_client("config_done.html")
                #form['twitter_auth'] = None
                return
            else:
                #global config
                RequestHandler.gen = setup_oauth(CONSUMER_KEY,CONSUMER_SECRET,verifier_queue)
                self._write_redirect_headers(RequestHandler.gen.next())
                RequestHandler.twitter_id = twitter_auth
                return
                #config[TwitterID]['OAUTH_TOKEN'] = OAUTH_TOKEN
                #config[TwitterID]['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET
                #with open('config.json', 'wb') as f:
                #    json.dump(config,f)

        self._writeheaders()
        if 'uname' in form.keys() and not re.match(r'^\w+$', form['uname'].value.strip().replace('_','')):
            logging.warning("you input invalid username %s" %form['uname'].value)
            with open("VERIFY_FAILED.html",'r') as f:
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))
                return

        if check_friendship(TwitterID,form['uname'].value.strip(),auth=oauth):
            logging.info("auth success %s" %form['uname'].value)
            with open("VERIFY_OK.html",'r') as f:
                self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))

            if self.client_address[0] in blocklist:
                logging.info("unblock the ip,feel free to use the wifi")
                os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j REDIRECT --to-ports 8888' %self.client_address[0])
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
        client = os.popen('arp -n').read().strip().split('\n')
        ip_mac = lambda s: re.findall(r'\d+\.\d+\.\d+\.\d+|\w+:\w+:\w+:\w+:\w+:\w+',s)
        ip_mac_list = map(ip_mac,client)
        logging.info('scan the arp list')
        for ipmac in ip_mac_list:
            if len(ipmac)==2 and (ipmac[1] in whitelist or ipmac[0] in authlist or ipmac[0] in blocklist):
                continue
            elif len(ipmac)==2:
                logging.info("the new client should be blocked.ip == %s,mac == %s" %(ipmac[0],ipmac[1]))
                blocklist.append(ipmac[0])
                os.system('iptables -t nat -I PREROUTING -s %s -p tcp --dport 80 -j REDIRECT --to-ports 8888' %ipmac[0])

        time.sleep(10)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    os.chdir(os.path.dirname(__file__) or '.')
    pathhome = os.path.join(os.path.dirname(__file__), os.pardir)
    pathconfig = os.path.join(pathhome,"twittrouter.json")
    if os.path.isfile(pathconfig):
        with open('twittrouter.json', 'rb') as f:
            config = json.load(f)
    else:
        with open('config.json', 'rb') as f:
            config = json.load(f)
    whitelist = config['whitelist'].split('|')
    TwitterID = config['TwitterID']
    CONSUMER_KEY = config['CONSUMER_KEY']
    CONSUMER_SECRET = config['CONSUMER_SECRET']
    OAUTH_TOKEN = config[TwitterID]["OAUTH_TOKEN"]
    OAUTH_TOKEN_SECRET = config[TwitterID]['OAUTH_TOKEN_SECRET']

    blocklist = []
    authlist = []
    verifier_queue = Queue.Queue(1)
    if not (TwitterID and CONSUMER_KEY and CONSUMER_SECRET):
        logging.critical("please add TwitterID,CONSUMER_KEY and CONSUMER_SECRET into config.json file")
        sys.exit(-1)
    """
    if not (OAUTH_TOKEN and OAUTH_TOKEN_SECRET):
        OAUTH_TOKEN,OAUTH_TOKEN_SECRET = setup_oauth(CONSUMER_KEY,CONSUMER_SECRET)
        config['OAUTH_TOKEN'] = OAUTH_TOKEN
        config['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET
        with open('config.json', 'wb') as f:
            json.dump(config,f)
    """
    print "Hi,@%s,thanks for sharing your wifi to your twitter friends" %TwitterID
    oauth = get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET)
    t = createThread(target = getarplist,args=tuple())
    serveraddr = ('', 8888)
    srvr = ThreadingHTTPServer(serveraddr, RequestHandler)
    srvr.serve_forever()
