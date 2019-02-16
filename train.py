import mitmproxy.http
import json
import statistics
from mitmproxy import ctx, http
import shelve
import os.path
if os.path.isfile("db3.json"):
    os.remove("db3.json")
if os.path.isfile("db4.json"):
    os.remove("db4.json")
if os.path.isfile("db4_1.json"):
    os.remove("db4_1.json")
if os.path.isfile("cse331_database.dat"):
    os.remove("cse331_database.dat")
if os.path.isfile("cse331_database.dir"):
    os.remove("cse331_database.dir")
if os.path.isfile("cse331_database.bak"):
    os.remove("cse331_database.bak")
if os.path.isfile("mnofpfesp.dat"):
    os.remove("mnofpfesp.dat")
if os.path.isfile("mnofpfesp.dir"):
    os.remove("mnofpfesp.dir")
if os.path.isfile("mnofpfesp.bak"):
    os.remove("mnofpfesp.bak")

db = shelve.open('cse331_database')
'''db is for the Maximum number of parameters seen for all requests across all pages '''
db["max"]=0
'''db2 is for the Maximum number of parameters seen for every specific page '''
db2 = shelve.open("mnofpfesp")
'''db3 is for the Character set of any specific parameter'''
db3={}
'''db4 is for the Average length of values for every specific parameter of every specific page '''
db4={}
import signal
import sys
def signal_handler(sig, frame):
        ctx.master.shutdown()
signal.signal(signal.SIGINT, signal_handler)


import urllib.parse as urlparse
class train:
    def __init__(self):
        self.num = 0
    def request(self, flow: mitmproxy.http.HTTPFlow):

        url = flow.request.url
        parsed = urlparse.urlparse(url)
        length = len(urlparse.parse_qs(parsed.query))
        wpath=parsed.netloc+parsed.path
        for i in urlparse.parse_qs(parsed.query).keys():
            value = str(urlparse.parse_qs(parsed.query)[i])[2:-2]
            char_used = list(value)
            path_db3= path_db4 = wpath+"_"+i
            if path_db3 not in db3.keys():
                db3[path_db3] = 0
            if path_db4 not in db4.keys():
                db4[path_db4] = []
            if not (value is None):
                temp = db4[path_db4][:]
                temp.append(len(value))
                db4[path_db4]=temp[:]
                if not value.isalnum():
                    db3[path_db3]=1

        if flow.request.method == "POST":
            body="?"+flow.request.content.decode()
            bodys=urlparse.urlparse(body)
            length+=len(urlparse.parse_qs(bodys.query))
            for i in urlparse.parse_qs(bodys.query).keys():
                value=str(urlparse.parse_qs(bodys.query)[i])[2:-2]
                char_used=list(value)
                path_db3 = path_db4 = wpath+"_"+i
                if path_db3 not in db3.keys():
                    db3[path_db3] = 0
                if path_db4 not in db4.keys():
                    db4[path_db4] = []
                if not (value is None):
                    temp = db4[path_db4][:]
                    temp.append(len(value))
                    db4[path_db4] = temp[:]
                    if not value.isalnum():
                        db3[path_db3] = 1

        if wpath not in db2.keys():
            db2[wpath] = length
        elif length > db2[wpath]:
            db2[wpath] = length

        if length > db["max"]:
            db["max"] = len(urlparse.parse_qs(parsed.query))

    def done(self):
        with open('db3.json', 'w') as f:
            json.dump(db3, f)
        with open('db4.json', 'w') as f:
            json.dump(db4, f)


addons = [
    train()
]