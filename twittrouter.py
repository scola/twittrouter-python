#!/usr/bin/env python
#coding=utf-8

from __future__ import with_statement
from __future__ import unicode_literals
import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'    
    
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
#from twfoller import check_friendship,get_oauth,setup_oauth
from requests_oauthlib import OAuth1
from urlparse import parse_qs

import requests
import cgi
import threading
import os
import time
import re
import logging
import Queue
import signal

REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize?oauth_token="
ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"

def setup_oauth(CONSUMER_KEY,CONSUMER_SECRET):
    while True:
        """Authorize your app via identifier."""
        # Request token
        oauth = OAuth1(CONSUMER_KEY, client_secret=CONSUMER_SECRET)
        r = requests.post(url=REQUEST_TOKEN_URL, auth=oauth)
        credentials = parse_qs(r.content)

        resource_owner_key = credentials.get('oauth_token')[0]
        resource_owner_secret = credentials.get('oauth_token_secret')[0]

        # Authorize
        authorize_url = AUTHORIZE_URL + resource_owner_key
        #print 'Please go here and authorize: ' + authorize_url

        #verifier = raw_input('Please input the verifier: ')
        yield authorize_url
        try:
            verifier = verifier_queue.get(timeout=2)
        except Empty:
            continue

        logging.info("get verifier = %s" %verifier)
        oauth = OAuth1(CONSUMER_KEY,
                       client_secret=CONSUMER_SECRET,
                       resource_owner_key=resource_owner_key,
                       resource_owner_secret=resource_owner_secret,
                       verifier=verifier)

        # Finally, Obtain the Access Token
        r = requests.post(url=ACCESS_TOKEN_URL, auth=oauth)
        credentials = parse_qs(r.content)
        token = credentials.get('oauth_token')[0]
        secret = credentials.get('oauth_token_secret')[0]
        logging.info("get token=%s secret=%s" %(token,secret))

        yield token, secret

def get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET):
    oauth = OAuth1(CONSUMER_KEY,
                client_secret=CONSUMER_SECRET,
                resource_owner_key=OAUTH_TOKEN,
                resource_owner_secret=OAUTH_TOKEN_SECRET)
    return oauth

def check_friendship(master,friend,auth):
    r = requests.get(url="https://api.twitter.com/1.1/friendships/lookup.json?screen_name=%s,%s" %(master,friend), auth=auth).json()
    return len(r) == 2 and (r[1]['connections'] != ['none'] or r[0]['connections'] != ['none'])

class RequestHandler(BaseHTTPRequestHandler,SimpleHTTPRequestHandler):
    twitter_id = None
    def send_to_client(self,filename):
        self._writeheaders()
        with open(filename,'r') as f:
            self.wfile.write(f.read().decode('utf-8').replace('twitterid',TwitterID).encode('utf-8'))
            self.wfile.close()

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
        if '/echo' == self.path and self.client_address[0] == '127.0.0.1':
            logging.info("echo to test the server")
            self._writeheaders()
            self.wfile.write("helloworld")
            self.wfile.close()

        elif "&oauth_verifier=" in self.path:
            logging.info("get oauth_verifier=%s" %self.path.split('=')[-1])
            verifier_queue.put(self.path.split('=')[-1])
            global oauth,TwitterID
            OAUTH_TOKEN,OAUTH_TOKEN_SECRET = gen.next()
            oauth = get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET)
            TwitterID = RequestHandler.twitter_id
            config["TwitterID"] = TwitterID
            new_auth = {}
            new_auth["OAUTH_TOKEN"] = OAUTH_TOKEN
            new_auth["OAUTH_TOKEN_SECRET"] = OAUTH_TOKEN_SECRET
            config[TwitterID] = new_auth
            with open(pathconfig, 'wb') as f:
                json.dump(config,f)
            self.send_to_client("config_done.html")
        elif "/config" == self.path and self.client_address[0] == "127.0.0.1":
            if TwitterID == "twitrouter":
                self.send_to_client("config.html")
            else:
                self.send_to_client("config_done.html")
        else:
            self.send_to_client("BASEHTML.html")

    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            keep_blank_values=True,
            environ={'REQUEST_METHOD':'POST',
            'CONTENT_TYPE':'text/html',
            })
        if self.client_address[0] == "127.0.0.1" and form and 'twitter_auth' in form and re.match(r'^\w+$', form['twitter_auth'].value.strip().replace('_','')):
            logging.info("auth input %s" %form['twitter_auth'].value)
            twitter_auth = form['twitter_auth'].value.strip()
            if twitter_auth in config.keys():
                global oauth,TwitterID
                TwitterID = twitter_auth
                OAUTH_TOKEN = config[twitter_auth]["OAUTH_TOKEN"]
                OAUTH_TOKEN_SECRET = config[twitter_auth]["OAUTH_TOKEN_SECRET"]
                oauth = get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET)

                self.send_to_client("config_done.html")
                return
            else:
                self._write_redirect_headers(gen.next())
                RequestHandler.twitter_id = twitter_auth
                return
        if not form or 'uname' not in form:
            return
            
        post_name = form['uname'].value.strip()
        if not re.match(r'^\w+$', post_name.replace('_','')):
            logging.warning("you input invalid username %s" %form['uname'].value)
            self.send_to_client("VERIFY_FAILED.html")
            return

        if check_friendship(TwitterID, post_name, auth=oauth):
            logging.info("auth success %s" %form['uname'].value)
            self.send_to_client("VERIFY_OK.html")

            if self.client_address[0] in blocklist:
                logging.info("unblock the ip,feel free to use the wifi")
                os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j REDIRECT --to-ports 8888' %self.client_address[0])
                blocklist.remove(self.client_address[0])
                authlist.append(self.client_address[0])
        else:
            self.send_to_client("VERIFY_FAILED.html")

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

def clear_iptables():
    logging.info("clearing iptables")
    iptables_list = os.popen('iptables -t nat -L PREROUTING').read().strip().split('\n')
    ip_port = lambda s: re.findall(r'\d+\.\d+\.\d+\.\d+|8888',s)
    ip_port_list = map(ip_port,iptables_list)
    for ip_port in ip_port_list:
        if len(ip_port) == 2:
            print ip_port[0]
            os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j REDIRECT --to-ports 8888' %ip_port[0])

def createThread(target,args):
    t = threading.Thread(target=target,args=args)
    t.setDaemon(1)
    t.start()
    return t

def getarplist():
    time.sleep(5)
    clear_iptables()
    while event.isSet():
        #client = os.popen('arp -n').read().strip().split('\n')
        with open('/proc/net/arp', 'r') as f:
            client = f.read().strip().split('\n')
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

def on_exit(no, info):
    logging.warning("on exit")
    event.clear()
    for ip in blocklist:
        os.system('iptables -t nat -D PREROUTING -s %s -p tcp --dport 80 -j REDIRECT --to-ports 8888' %ip)
    clear_iptables()
    os.kill(os.getpid(),signal.SIGINT)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    os.chdir(os.path.dirname(__file__) or '.')
    pathhome = os.path.join(os.path.dirname(__file__), os.pardir)
    pathconfig = os.path.join(pathhome,"twittrouter.json")
    if os.path.isfile(pathconfig):
        with open(pathconfig, 'rb') as f:
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
    event = threading.Event()
    event.set()

    if not (TwitterID and CONSUMER_KEY and CONSUMER_SECRET):
        logging.critical("please add TwitterID,CONSUMER_KEY and CONSUMER_SECRET into config.json file")
        sys.exit(-1)

    print "Hi,@%s,thanks for sharing your wifi to your twitter friends" %TwitterID
    oauth = get_oauth(CONSUMER_KEY,CONSUMER_SECRET,OAUTH_TOKEN,OAUTH_TOKEN_SECRET)
    gen = setup_oauth(CONSUMER_KEY,CONSUMER_SECRET)
    signal.signal(signal.SIGTERM, on_exit)
    t = createThread(target = getarplist,args=tuple())
    serveraddr = ('', 8888)
    srvr = ThreadingHTTPServer(serveraddr, RequestHandler)
    srvr.serve_forever()
