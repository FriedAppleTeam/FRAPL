#
#  MemoryEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import json

from idaapi import Choose2

from ..Core.Types import MemoryRegion

from ..UI.ViewStore import ViewStore
from ..UI.MemoryView import MemoryView
from ..UI.MemoryManagerView import MemoryManagerView
from ..Utils.Logging import fl_log as fl_log
from ..Common.MessageTypes import *

class MemoryEngineProtocol(object):

	def __init__(self):
		super(MemoryEngineProtocol, self).__init__()
		self.memoryMap = {}
		self.memoryViews = ViewStore()
		self.memoryManager = MemoryManagerView(self)
		self.modalMemManager = None

	def backupMemoryData(self):
		return self.memoryMap

	def restoreMemoryData(self, data):
		self.memoryMap = data
		self.syncMemoryRegions()

	def syncMemoryRegions(self):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		fl_log("FridaLink: sync memory ranges...\n")
		# stop monitoring all memory regions
		outJSON = json.dumps({
			"req_id": kFridaLink_DelMemRequest, 
			"data": { "all": True }
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

		# sync memory regions
		for mem_id in self.memoryMap:
			outJSON = json.dumps({
				"req_id": kFridaLink_AddMemRequest, 
				"data": self.memoryMap[mem_id].serialize()
			})
			self.clientSocket.sendto(outJSON, self.clientAddress)

	def fetchMemoryRange(self, mem_id):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		outJSON = json.dumps({
			"req_id": kFridaLink_FetchMemRequest, 
			"data": self.memoryMap[mem_id].serialize()
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)


	def handleMemoryFetchResponse(self, platform, arch, response):
		self.updateMemoryContent(response['mem_id'], response['content'])

	def generateMemoryID(self, address):
		idx = 0
		mem_id = "0x%X_%d" % (address, idx)
		while mem_id in self.memoryMap:
			idx += 1
			mem_id = "0x%X_%d" % (address, idx)
		return mem_id

	def addMemoryRegion(self, address, size, comment):
		# ask address and size
		mem_id = self.generateMemoryID(address)
		region = MemoryRegion(mem_id, address, size, comment)
		self.memoryMap[mem_id] = region
		self.memoryManager.setContent(self.memoryMap)
		if self.modalMemManager is not None:
			self.modalMemManager.setContent(self.memoryMap)

		if self.clientSocket is not None:
			outJSON = json.dumps({
				"req_id": kFridaLink_AddMemRequest, 
				"data": region.serialize()
			})
			self.clientSocket.sendto(outJSON, self.clientAddress)

	def delMemoryRegion(self, mem_id):
		if mem_id in self.memoryMap:
			region = self.memoryMap[mem_id]
			del self.memoryMap[mem_id]
			self.memoryManager.setContent(self.memoryMap)
			if self.modalMemManager is not None:
				self.modalMemManager.setContent(self.memoryMap)

			self.handleMemoryRemoval(mem_id)

			if self.clientSocket is not None:
				outJSON = json.dumps({
					"req_id": kFridaLink_DelMemRequest, 
					"data": { 
						"all": 		False,
						"mem_id":	mem_id
					}
				})
				self.clientSocket.sendto(outJSON, self.clientAddress)

	def showMemoryManager(self):
		self.memoryManager.setContent(self.memoryMap)
		self.memoryManager.show(False)

	def linkMemoryRanges(self):
		self.modalMemManager = MemoryManagerView(self, flags=Choose2.CH_MULTI)
		self.modalMemManager.setContent(self.memoryMap)
		self.modalMemManager.show(True)
		linkList = self.modalMemManager.linkList
		self.modalMemManager = None
		return [ linkList[x] for x in range(len(linkList)) ]

	def updateMemoryContent(self, mem_id, content):
		if mem_id in self.memoryMap:
			self.memoryMap[mem_id].content = content
			if self.memoryViews.hasView(mem_id):
				self.memoryViews.setContent(mem_id, content)

	def showMemoryView(self, view_id):
		if self.memoryViews.hasView(view_id) == False:
			newView = MemoryView(self, view_id, self.memoryMap[view_id].address)
			self.memoryViews.addView("Memory", newView)
		self.memoryViews.setContent(view_id, self.memoryMap[view_id].content)
		self.memoryViews.showView(view_id)

	def memoryViewClosed(self, view_id):
		self.memoryViews.delView(view_id)

__all__ = [
    'MemoryEngineProtocol'
]
