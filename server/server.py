#!/usr/bin/env python
# -*- coding: utf-8 -*-
from twisted.internet import reactor 
from twisted.web import static, server 
from twisted.web.resource import Resource

from devicemanager import DeviceManager
devices=DeviceManager()

class JSonInterface(Resource):
	def getChild(self, name, request):
		return self
	def render_POST(self, request):
		server.parseCheckin(request.content.read(),request.getClientIP())
	def render_GET(self, request):
		return str(request.args)

root = Resource()
root.putChild("json", JSonInterface())

site = server.Site(root()) 
reactor.listenTCP(25000, site) 
reactor.run()