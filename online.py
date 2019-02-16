import mitmproxy.http
from mitmproxy import ctx, http
import shelve
import statistics
db = shelve.open('cse331_database')
db2= shelve.open('mnofpfesp')
import urllib.parse as urlparse
import json
class online:
    def __init__(self):
        self.num = 0

    def request(self, flow: mitmproxy.http.HTTPFlow):

        request_headers = flow.request.headers
        agents = request_headers["User-Agent"]
        if "<script>" in agents:
            #print("Detect basic XSS ATTACK through User-Agent Header")
            flow.response = http.make_error_response(403, "Detect basic XSS ATTACK through User-Agent Header")
        if "bot" in agents:
            #print("Deny all requests from hosts that identify themselves as bots")
            flow.response = http.make_error_response(403, "Firewall: Deny all requests from hosts that identify themselves as bots.")
        method = flow.request.method
        if method == "GET":
            if "union%20all%20select" in flow.request.url or ("EXTRACTVALUE" in flow.request.url):
                #print("Search all parameters of GET Requests for possible SQL Injection")
                flow.response = http.make_error_response(403, "Firewall: Deny all requests for possible SQL Injection")
        url = flow.request.url
        parsed = urlparse.urlparse(url)
        dictMerged = urlparse.parse_qs(parsed.query)
        # print("dict used to be :", dictMerged)
        if flow.request.method == "POST":
            body = "?" + flow.request.content.decode()
            bodys = urlparse.urlparse(body)
            if "foo" in (urlparse.parse_qs(bodys.query)).keys():
                if "../../../../" in urlparse.parse_qs(bodys.query)["foo"]:
                    flow.response = http.make_error_response(403, "Firewall: Deny all requests for possible Directory Traversal vulnerabilities")
            dictMerged.update(urlparse.parse_qs(bodys.query))
        length = len(urlparse.parse_qs(parsed.query))
        wpath = parsed.netloc + parsed.path
        '''check the first part'''
        if len(urlparse.parse_qs(parsed.query)) > db["max"]:
            flow.response = http.make_error_response(403,"Firewall: Detect an Anomaly. drop requests that exceed that maximum number")
        '''check the second part'''
        if wpath in db2.keys():
            if length > db2[wpath]:
                flow.response = http.make_error_response(403,"Firewall: Detect an Anomaly. drop requests that exceed that maximum number for a specific page")
        '''check the third part'''
        with open("db3.json", 'r') as load_file:
            db3 = json.load(load_file)
            for i in dictMerged.keys():
                value=str(dictMerged[i])[2:-2]
                path_of_dict=wpath+"_"+i
                if path_of_dict in db3.keys():
                    if  (not value.isalnum()) and db3[path_of_dict]==0 :
                        flow.response = http.make_error_response(403,"Firewall: Detect an Anomaly. drop requests with parameters containing character from sets not seen during training")
        '''check part 4'''
        with open("db4_1.json", 'r') as load_file:
            db4 = json.load(load_file)
            for i in dictMerged.keys():
                value = str(dictMerged[i])[2:-2]
                path_of_dict = wpath + "_" + i
                length = len(value)
                if path_of_dict in db4.keys():
                    sdv = db4[path_of_dict][1]
                    mean = db4[path_of_dict][0]
                    if not ((mean - 3 * sdv) < length < (mean + 3 * sdv)):
                        print("mean is :",mean)
                        print("sdv is :", sdv)
                        print("length is :", length)
                        print("i :",path_of_dict)
                        flow.response = http.make_error_response(403, "Firewall: Detect an Anomaly. drop all values that are not part of the mean+-3*sd")
    def running(self):
        db4_1 = {}
        with open("db4.json", 'r') as load_file:
            db4 = json.load(load_file)
            for i in db4.keys():
                if len(db4[i]) >= 4:
                    db4_1[i] = [statistics.mean(db4[i]), statistics.stdev(db4[i])]
                else:
                    db4_1[i] = [statistics.mean(db4[i]), statistics.mean(db4[i])/10]
        with open("db4_1.json", 'w') as load_file:
            json.dump(db4_1, load_file)


addons = [
    online()
]