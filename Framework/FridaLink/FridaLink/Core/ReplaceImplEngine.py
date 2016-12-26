#
#  ReplaceImplEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import json
import os

from idaapi import refresh_idaview_anyway
from idaapi import get_func, get_func_name
from idc import ScreenEA, SetColor, CIC_ITEM, CIC_FUNC

from ..Core.Types import FuncReplace
from ..UI.FunctionReplaceDialog import FunctionReplaceDialog
from ..UI.FuncReplaceListView import FuncReplaceListView
from ..UI.Colors import *
from ..Utils.Logging import fl_log as fl_log

from ..Common.MessageTypes import *

class ReplaceImplEngineProtocol(object):
	def __init__(self):
		super(ReplaceImplEngineProtocol, self).__init__()
		self.funcReplaceMap = {}
		self.funcReplaceView = FuncReplaceListView(self)

	def resetReplacedColors(self):
		for key in self.funcReplaceMap:
			entry = self.funcReplaceMap[key]
			SetColor(entry.id, CIC_ITEM, kIDAViewColor_Reset)
		refresh_idaview_anyway()

	def backupReplacedFuncData(self):
		return self.funcReplaceMap

	def restoreReplacedFuncData(self, data):
		self.funcReplaceMap = data
		self.syncReplacedFuncs()

	def deleteAllReplaced(self):
		# delete all replaced functions
		outJSON = json.dumps({
			"req_id": kFridaLink_DelReplaceRequest, 
			"data": {
				"all":	True
			}
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def syncReplacedFuncs(self):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		for key in self.funcReplaceMap:
			entry = self.funcReplaceMap[key]
			outJSON = json.dumps({
				"req_id": kFridaLink_SetReplaceRequest, 
				"data": entry.genSetRequest()
			})

			if entry.moduleImport == False:
				SetColor(entry.hook.id, CIC_ITEM, kIDAViewColor_ReplacedFunc)

			self.clientSocket.sendto(outJSON, self.clientAddress)
		refresh_idaview_anyway()

	def handleReplaceFunc(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		address = func.startEA;

		offset, moduleName = self.getAddressDetails(address)

		replaceDlg = FunctionReplaceDialog(moduleName, "%X" % address, get_func_name(address), None)
		replaceDlg.Compile()
		replaceDlg.script.value = ""
		ok = replaceDlg.Execute()
		if ok != 1:
			return

		replace = FuncReplace()
		replace.id = address
		replace.symbol = get_func_name(address)
		replace.address = offset
		replace.module = moduleName
		replace.moduleImport = False
		replace.ret_type = "\'" + replaceDlg.ret_type.value + "\'"
		replace.recentSrcFile = replaceDlg.recentScriptFile
		replace.script = replaceDlg.script.value
		replace.args_str = replaceDlg.args.value
		replace.arg_types = ""
		replace.arg_names = ""

		if replace.args_str != "":
			args_list = replace.args_str.split(",")

			for arg in args_list:
				arg_list = arg.split()
				replace.arg_types += "\'" + arg_list[0] + "\', "
				replace.arg_names += arg_list[1] + ", " 

			replace.arg_types = replace.arg_types[:-2]
			replace.arg_names = replace.arg_names[:-2]

		outJSON = json.dumps({
			"req_id": kFridaLink_SetReplaceRequest, 
			"data": replace.genSetRequest()
		})

		SetColor(address, CIC_FUNC, kIDAViewColor_ReplacedFunc)
		refresh_idaview_anyway()
		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.funcReplaceMap[address] = replace

		self.funcReplaceView.setContent(self.funcReplaceMap)

	def handleReplaceImportSymbolForIdx(self, import_idx):
		importEntry = self.imports[import_idx]

		# if symbol already replaced, open edit dialog
		if importEntry.address in self.funcReplaceMap:
			self.handleReplaceFuncEdit(importEntry.address)
			return

		replaceDlg = FunctionReplaceDialog(os.path.basename(importEntry.module), "%X" % importEntry.address, importEntry.symbol, None)
		replaceDlg.Compile()
		replaceDlg.script.value = ""
		ok = replaceDlg.Execute()
		if ok != 1:
			return

		replace = FuncReplace()
		replace.id = importEntry.address
		replace.symbol = importEntry.symbol
		replace.address = importEntry.address
		replace.module = os.path.basename(importEntry.module)
		replace.moduleImport = True
		replace.ret_type = "\'" + replaceDlg.ret_type.value + "\'"
		replace.recentSrcFile = replaceDlg.recentScriptFile
		replace.script = replaceDlg.script.value
		replace.args_str = replaceDlg.args.value
		replace.arg_types = ""
		replace.arg_names = ""

		if replace.args_str != "":
			args_list = replace.args_str.split(",")

			for arg in args_list:
				arg_list = arg.split()
				replace.arg_types += "\'" + arg_list[0] + "\', "
				replace.arg_names += arg_list[1] + ", " 

			replace.arg_types = replace.arg_types[:-2]
			replace.arg_names = replace.arg_names[:-2]

		outJSON = json.dumps({
			"req_id": kFridaLink_SetReplaceRequest, 
			"data": replace.genSetRequest()
		})

		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.funcReplaceMap[importEntry.address] = replace

		self.funcReplaceView.setContent(self.funcReplaceMap)

	def handleReplaceFuncEdit(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		repl_id = func.startEA;

		if repl_id not in self.funcReplaceMap:
			return

		entry = self.funcReplaceMap[repl_id]

		replaceDlg = FunctionReplaceDialog(entry.module, "%X" % entry.id, entry.symbol, entry.recentSrcFile)
		replaceDlg.Compile()
		replaceDlg.ret_type.value = entry.ret_type[1:-1]
		replaceDlg.args.value = entry.args_str
		replaceDlg.script.value = entry.script
		ok = replaceDlg.Execute()
		if ok != 1:
			return

		flags = FuncReplace.UDP_NONE

		entry.recentSrcFile = replaceDlg.recentScriptFile
		if entry.script != replaceDlg.script.value:
			entry.script = replaceDlg.script.value
			flags |= FuncReplace.UPD_SCRIPT

		outJSON = json.dumps({
			"req_id": kFridaLink_UpdReplaceRequest, 
			"data": entry.genUpdRequest(flags)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleReplaceFuncDel(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		repl_id = func.startEA;

		if repl_id not in self.funcReplaceMap:
			return

		entry = self.funcReplaceMap[repl_id]

		outJSON = json.dumps({
			"req_id": kFridaLink_DelReplaceRequest, 
			"data": entry.genDelRequest()
		})

		del self.funcReplaceMap[repl_id]
		self.clientSocket.sendto(outJSON, self.clientAddress)

		if entry.moduleImport == False:
			SetColor(repl_id, CIC_FUNC, kIDAViewColor_Reset)
			refresh_idaview_anyway()

		self.funcReplaceView.setContent(self.funcReplaceMap)

	def showReplacedFuncs(self):
		self.funcReplaceView.setContent(self.funcReplaceMap)
		self.funcReplaceView.show()

	def handleReplaceResponse(self, response):
		repl_id = int(response['id'], 16)
		if repl_id not in self.funcReplaceMap:
			return
		
		entry = self.funcReplaceMap[repl_id]

		# unable to install hook
		if response['count'] == 0:
			if entry.moduleImport == False:
				SetColor(repl_id, CIC_FUNC, kIDAViewColor_Reset)
				refresh_idaview_anyway()
			del self.funcReplaceMap[repl_id]
			self.funcReplaceView.setContent(self.funcReplaceMap)

	def replacedFunction(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())

		if func is None:
			return False;

		address = func.startEA;
		if address in self.funcReplaceMap:
			return True
		else:
			return False

__all__ = [
    'ReplaceImplEngineProtocol'
]
