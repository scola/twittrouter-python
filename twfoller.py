# -*- encoding: utf-8 -*-
from __future__ import unicode_literals
import requests
from requests_oauthlib import OAuth1
from urlparse import parse_qs

REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize?oauth_token="
ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"

#CONSUMER_KEY = ""
#CONSUMER_SECRET = ""

#OAUTH_TOKEN = ""
#OAUTH_TOKEN_SECRET = ""


def setup_oauth(CONSUMER_KEY,CONSUMER_SECRET,verifier_queue):
    """Authorize your app via identifier."""
    # Request token
    oauth = OAuth1(CONSUMER_KEY, client_secret=CONSUMER_SECRET)
    r = requests.post(url=REQUEST_TOKEN_URL, auth=oauth)
    credentials = parse_qs(r.content)

    resource_owner_key = credentials.get('oauth_token')[0]
    resource_owner_secret = credentials.get('oauth_token_secret')[0]
    
    # Authorize
    authorize_url = AUTHORIZE_URL + resource_owner_key
    print 'Please go here and authorize: ' + authorize_url
    
    #verifier = raw_input('Please input the verifier: ')
    yield authorize_url
    verifier = verifier_queue.get()
    print "get verifier = %s" %verifier
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
    print "get token=%s secret=%s" %(token,secret)

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

if __name__ == "__main__":
    pass
