#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
from datetime import datetime, timedelta

class Server:
	devices = {
		"aa-bb-cc-dd-ee-ff": {
			"type": "simulation",
		}
	}
	locations={}
	
	def parseTime(self,secondsago):
		return datetime.now()-timedelta(0,secondsago)
	
	def parseCheckin(self,checkInData):
		
		checkInData=json.loads(checkInData)
		
		mac_address=checkInData["mac_address"]
		
		if checkInData["software_version"]!="ed0877e4d874ad81947ddd8305c8c74c1c73afc2":
			print Error("Incompatible version %s for device %s" % (checkInData["software_version"],mac_address))
		
		self.locations[mac_address]=dict([(self.parseTime(int(k)),v) for k,v in checkInData["location"].items()])
		
		for time in self.locations[mac_address].keys():
			self.solveLocation(mac_address,time)
	
	def solveLocation(self,device,time):
		self.locations[device][time]["location"]="TODO"
	
	def deviceStatus(self,mac):
		try:
			device=self.devices[mac]
			print "Device Mac Address: %s" % (mac)
			print "Device Type: %s" % (device["type"])
		except KeyError:
			raise Error("No such device tracked")
		
		try:
			locations=self.locations[mac]
			print "Number of CheckIn locations: %s" % (len(locations))
			lastCheckIn=sorted(locations.keys())[-1]
		except KeyError:
			raise Error("No data exists on device %s" % (mac))
		
		ways=[way for way in locations[lastCheckIn].keys() if way!="location"]
		print "Last known location @%s via %s:\n%s" % (lastCheckIn,', '.join(ways),locations[lastCheckIn]["location"])

server=Server()
server.parseCheckin(open(sys.argv[1]).read())
server.deviceStatus(server.locations.keys()[0])