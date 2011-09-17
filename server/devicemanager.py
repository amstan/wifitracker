#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
from urllib2 import urlopen
from datetime import datetime, timedelta
import logging

def printDict(dictionary,indent=0):
	for key in dictionary.keys():
		if type(dictionary[key]) is not dict:
			print "%s%s: %s" % (" "*indent,key, dictionary[key])
		else:
			print "%s%s:" % (" "*indent,key)
			printDict(dictionary[key],indent+2)

class DeviceManager:
	devices = {
		"aa-bb-cc-dd-ee-ff": {
			"type": "simulation",
		}
	}
	locations={}
	
	def __init__(self):
		for device in self.devices.keys():
			self.locations[device]={}
	
	def parseTime(self,secondsago):
		return datetime.now()-timedelta(0,secondsago)
	
	def parseCheckin(self,checkInData,ipaddress="0.0.0.0"):
		"""Parses the checkin and stores it in the database"""
		checkInData=json.loads(checkInData)
		mac_address=checkInData["mac_address"]
		
		if mac_address not in self.devices.keys():
			raise Exception("Unknown device %s." % (mac_address))
		
		if checkInData["software_version"]!="ed0877e4d874ad81947ddd8305c8c74c1c73afc2":
			raise Exception("Incompatible version %s for device %s" % (checkInData["software_version"],mac_address))
		
		checkInData["location"]=dict([(self.parseTime(int(k)),v) for k,v in checkInData["location"].items()])
		
		self.devices[mac_address]["battery"]=checkInData["battery"]
		
		for key in checkInData["location"].keys():
			checkInData["location"][key]["ipaddress"]=ipaddress
			self.locations[mac_address][key]=checkInData["location"][key]
		
		logging.info("CheckIn from %s" % mac_address)
	
	def solveLocation(self,device,time):
		request=self.locations[device][time]
		request["version"]="1.1.0"
		request["request_address"]="True"
		request["address_language"]="en_GB"
		response=json.loads(urlopen("https://www.google.com/loc/json",json.dumps(request)).read())
		self.locations[device][time]["location"]=response["location"]
		logging.info("Solving location for %s from time %s" % (device,time))
	
	def deviceStatus(self,mac):
		try:
			device=self.devices[mac]
			print "Device Mac Address: %s" % (mac)
			print "Device Type: %s" % (device["type"])
		except KeyError:
			raise Exception("No such device tracked")
		
		try:
			locations=self.locations[mac]
			print "Number of CheckIn locations: %s" % (len(locations))
			lastCheckIn=sorted(locations.keys())[-1]
		except KeyError:
			raise Exception("No data exists on device %s" % (mac))
		
		ways=[way for way in locations[lastCheckIn].keys() if way!="location"]
		
		if "location" not in locations[lastCheckIn].keys():
			self.solveLocation(mac,lastCheckIn)
			
		print "Last known battery level: %s" % (self.devices[mac]["battery"])
		print "Last known location @%s via %s:" % (lastCheckIn,', '.join(ways))
		printDict(locations[lastCheckIn]["location"],2)
		
		return locations[lastCheckIn]["location"]

if __name__ == '__main__':
	logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
	
	import sys
	server=DeviceManager()
	server.parseCheckin(open(sys.argv[1]).read())
	server.deviceStatus(server.locations.keys()[0])