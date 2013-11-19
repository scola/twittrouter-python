#!/usr/bin/env python
#coding=utf-8

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
import cgi
import threading
import sys
import os
import time
import re
import subprocess


BASEHTML = ''
VERIFY_OK = ''
VERIFY_FAILED = ''

whitelist = []
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
        if self.path == '/':
            self._writeheaders()
            with open("BASEHTML.html",'r') as f:
                self.wfile.write(f.read())
        else:
            SimpleHTTPRequestHandler.do_GET(self)
    def do_POST(self): 
        form = cgi.FieldStorage( 
            fp=self.rfile, 
            headers=self.headers, 
            environ={'REQUEST_METHOD':'POST', 
            'CONTENT_TYPE':self.headers['Content-Type'], 
            }) 
        self._writeheaders()
        if form['uname'].value == 'shaozhengwu':
            with open("VERIFY_OK.html",'r') as f:
                self.wfile.write(f.read())
        else:    
            with open("VERIFY_FAILED.html",'r') as f:
                self.wfile.write(f.read())
        print self.client_address[0]        
        return   

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass    
    
def createThread(target,args):
    t = threading.Thread(target=target,args=args)
    t.setDaemon(1)
    t.start()
    #t.join()
    return t
    
def getarplist():
    client = os.popen('arp').read().strip().split('\n')[1:]
 
    
if __name__ == "__main__":   

    t = createThread(target = getarplist,args=None)
    serveraddr = ('', 8765)
    srvr = ThreadingHTTPServer(serveraddr, RequestHandler)
    srvr.serve_forever()
