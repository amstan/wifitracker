#!/usr/bin/python
import csv,time,sys,os,json
#print open("data").read().replace("\0", "")
reader = csv.reader(open("data2"))
table = [];

starttime=time.mktime(time.strptime(" 2010-05-13 20:30:00"," %Y-%m-%d %H:%M:%S"))
currenttime=starttime

for row in reader:
	if row:
		row[0]=row[0].replace(":", "-")
		row[1]=time.strptime(row[1]," %Y-%m-%d %H:%M:%S")
		row[2]=time.strptime(row[2]," %Y-%m-%d %H:%M:%S")
	table.append(row);

def timediff(a,b):
	a=time.mktime(a);
	b=time.mktime(b);
	#print abs(a-b)
	if(abs(a-b)<5):
		return 1

def selector(x):
	global currenttime
	y=currenttime
	#y=time.strptime(currenttime," %Y-%m-%d %H:%M:%S")
	if x:
		#print x
		if(timediff(x[1],y)):
			return 1
		if(timediff(x[1],y)):
			return 1

for i in range(1,240*3):
	currenttime=time.localtime(starttime+i*5)
	closenetworks=filter(selector,table)
	
	#print closenetworks
	if len(closenetworks)>2:
		#print time.strftime("%Y-%m-%d %H:%M:%S",currenttime)
		closenetworks=closenetworks[:2]
		
		post="{\"version\": \"1.1.0\",\"request_address\": true,\"address_language\": \"en_GB\",\"wifi_towers\": ["
		post+="{\"mac_address\": \"" + closenetworks[0][0] + "\",\"signal_strength\": 8,\"age\": 0},"
		
		post+="{\"mac_address\": \"" + closenetworks[1][0] + "\",\"signal_strength\": 6,\"age\": 0}"
		#post+="{\"mac_address\": \"" + closenetworks[2][0] + "\",\"signal_strength\": 4,\"age\": 0}"
		#print "---"
		post+="]}"
		post=post.replace("\"","\\\"")
		
		response=json.loads(os.popen("wget -qO- https://www.google.com/loc/json --post-data=\""+post+"\"", "r").read())
		print "http://maps.google.com/maps?f=q&source=s_q&hl=en&geocode=&q="+str(response['location']['latitude']) + "," + str(response['location']['longitude'])