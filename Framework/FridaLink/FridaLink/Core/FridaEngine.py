#
#  FridaEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import json

from idaapi import get_segm_by_name, get_func_name, get_func
from idc import GetDisasm, ScreenEA

from ..UI.ExecuteScriptDialog import ExecuteScriptDialog
from ..UI.ConvertAddressDialog import ConvertAddressDialog
from ..UI.ModuleListView import ModuleListView
from ..Utils.Logging import fl_log as fl_log

from ..Common.MessageTypes import *

class FridaEngineProtocol(object):
	def __init__(self):
		super(FridaEngineProtocol, self).__init__()
		self.targetArch = None
		self.targetPlatform = None
		self.execScript = ""
		self.recentScriptFile = None
		self.targetModules = []
		self.moduleListView = ModuleListView(self)

	def backupFridaData(self):
		return [ self.execScript, self.recentScriptFile, self.targetModules ]

	def restoreFridaData(self, data):
		self.execScript = data[0]
		self.recentScriptFile = data[1]
		self.targetModules = data[2]

	def getModuleBase(self, index):
		return int(self.targetModules[index]["base"], 16)

	def getModuleName(self, index):
		return self.targetModules[index]["name"]

	def getModuleNamesList(self):
		ret = []
		for module in self.targetModules:
			ret.append(str(module["name"]))
		return ret

	def requestModules(self):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		fl_log("FridaLink: requesting target modules...\n")
		outJSON = json.dumps({
			"req_id": kFridaLink_ModulesRequest, 
			"data": None
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def getTargetPlatform(self):
		return self.targetPlatform

	def getTargetArch(self):
		return self.targetArch

	def handleTargetInfo(self, platform, arch):
		fl_log("FridaLink: Target [ %s, %s ]\n" % (platform, arch))
		self.targetArch = arch
		self.targetPlatform = platform

	def handleModulesResponse(self, modules):
		self.targetModules = modules
		self.moduleListView.setContent(self.targetModules)

	def resolveStackAddress(self, address, symbol):
		if symbol[0] == "0x0":
			return None

		info = {}
		info['module'] = str(symbol[1])
		segm = get_segm_by_name(info['module'])
		if segm is not None:
			locEA = segm.startEA
			delta = address - int(symbol[0], 16) + locEA
			func = get_func(delta)
			if func is not None:
				info['symbol'] = str(get_func_name(delta))
			else:
				info['symbol'] = str(GetDisasm(delta))
		elif symbol[2] != '':
			if symbol[2] == '<redacted>':
				info['symbol'] = "+0x%X" % (address - int(symbol[0], 16))
			else:
				info['symbol'] = str(symbol[2])
		else:
			info['symbol'] = ''

		return info

	def showModuleList(self):
		self.moduleListView.show()

	def showExecScriptDlg(self):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		execScriptDlg = ExecuteScriptDialog(self, self.recentScriptFile)
		execScriptDlg.Compile()
		execScriptDlg.script.value = self.execScript
		ok = execScriptDlg.Execute()
		if ok == 1:
			self.execScript = execScriptDlg.script.value
			self.recentScriptFile = execScriptDlg.recentScriptFile

	def showAddressConverter(self):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return
		convertDlg = ConvertAddressDialog(self, self.getModuleNamesList())
		convertDlg.Compile()
		convertDlg.Execute()

	def executeScript(self, script):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		outJSON = json.dumps({
			"req_id": kFridaLink_ExecuteScript, 
			"data": script
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleGetRealAddress(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		offset, moduleName = self.getAddressDetails(address)
		for module in self.targetModules:
			if module['name'] == moduleName:
				moduleBase = module['base']
				realAddr = int(moduleBase,16) + offset
				self.handleFraplLog("info", "[ %s ] 0x%X => 0x%X %s" % (moduleName, address, realAddr, GetDisasm(address)))
				break

__all__ = [
    'FridaEngineProtocol'
]
