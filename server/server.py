#!/usr/bin/env python
# -*- coding: utf-8 -*-
from twisted.internet import reactor 
from twisted.web import static, server 
from twisted.web.resource import Resource

import logging
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

from devicemanager import DeviceManager
devices=DeviceManager()

import sys
class WritableObject:
	def __init__(self):
		self.content = []
	def write(self, string):
		self.content.append(string)
	def dump(self):
		dump=self.content
		self.content=[]
		return str(''.join(dump))
WritableObject=WritableObject()

class JSonInterface(Resource):
	def getChild(self, name, request):
		return self
	def render_POST(self, request):
		devices.parseCheckin(request.content.read(),request.getClientIP())
		return str("Checkin succeeded.")

class deviceStatus(Resource):
	def getChild(self, name, request):
		return self
	def render_GET(self, request):
		sys.stdout = WritableObject
		
		for device in request.args["device"]:
			print "<pre>"
			location=devices.deviceStatus(device)
			print "</pre>"
			print ("<a href=\"http://maps.google.com/maps?f=q&source=s_q&hl=en&geocode=&q=%s,%s\">Last Known Location Map</a>" % (location["latitude"],location["longitude"]))
			print "<hr>"
		
		sys.stdout = sys.__stdout__
		
		return WritableObject.dump()

root = Resource()
root.putChild("json", JSonInterface())
root.putChild("deviceStatus", deviceStatus())

factory = server.Site(root)
reactor.listenTCP(13000, factory)
reactor.run()
