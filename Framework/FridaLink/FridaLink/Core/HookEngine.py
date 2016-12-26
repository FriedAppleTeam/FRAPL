#
#  HookEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import json
import os

from idaapi import refresh_idaview_anyway
from idaapi import get_func, get_func_name
from idaapi import get_prev_seg, get_segm_name
from idc import ScreenEA, SegName, GetDisasm
from idc import SetColor, CIC_ITEM, CIC_FUNC

from ..Common.Config import DevModeEnabled

from ..Core.Types import HookEntry, InstHook, FuncHook
from ..UI.ViewStore import ViewStore
from ..UI.BacktraceView import BacktraceView
from ..UI.StackView import StackView
from ..UI.CPUContextView import CPUContextView
from ..UI.IdbHookListView import IdbHookListView
from ..UI.ImportHookListView import ImportHookListView
from ..UI.InstructionHookDialog import InstructionHookDialog
from ..UI.FunctionHookDialog import FunctionHookDialog
from ..UI.Colors import *
from ..Utils.Logging import fl_log as fl_log

from ..Common.MessageTypes import *

if DevModeEnabled() == True:
	from ..UI import InstructionHookDialog as dlg1
	from ..UI import FunctionHookDialog as dlg2
	reload(dlg1)
	reload(dlg2)

kModuleAlignment = 0x10000000

class HookEngineProtocol(object):

	def __init__(self):
		super(HookEngineProtocol, self).__init__()
		self.cpuContextViews = ViewStore()
		self.stackViews =  ViewStore()
		self.idbHooksView = IdbHookListView(self)
		self.idbHookMap = {}
		self.importHooksView = ImportHookListView(self)
		self.importHookMap = {}

	def resetHookedColors(self):
		for key in self.idbHookMap:
			entry = self.idbHookMap[key]
			if entry.hook.type == "inst":
				SetColor(entry.hook.id, CIC_ITEM, kIDAViewColor_Reset)
			elif entry.hook.type == "func":
				SetColor(entry.hook.id, CIC_FUNC, kIDAViewColor_Reset)
			refresh_idaview_anyway()

	def deleteAllHooks(self):
		# delete all hooks
		outJSON = json.dumps({
			"req_id": kFridaLink_DelHookRequest, 
			"data": {
				"all":	True
			}
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def backupHookData(self):
		return [ self.idbHookMap, self.importHookMap ]

	def restoreHookData(self, data):
		self.idbHookMap = data[0]
		self.syncIdbHooks()
		self.importHookMap = data[1]
		self.syncImportHooks()

	def syncIdbHooks(self):
		# install IDB hooks
		for key in self.idbHookMap:
			entry = self.idbHookMap[key]
			outJSON = json.dumps({
				"req_id": kFridaLink_SetHookRequest, 
				"data": entry.genSetRequest()
			})

			if entry.hook.type == "inst":
				SetColor(entry.hook.id, CIC_ITEM, kIDAViewColor_HookedInst)
			elif entry.hook.type == "func":
				SetColor(entry.hook.id, CIC_FUNC, kIDAViewColor_HookedFunc)
			self.clientSocket.sendto(outJSON, self.clientAddress)
		refresh_idaview_anyway()

	def syncImportHooks(self):
		# install Import hooks
		for key in self.importHookMap:
			entry = self.importHookMap[key]
			outJSON = json.dumps({
				"req_id": kFridaLink_SetHookRequest, 
				"data": entry.genSetRequest()
			})

			self.clientSocket.sendto(outJSON, self.clientAddress)

	def backupCpuViews(self):
		return self.cpuContextViews

	def refreshCpuViews(self):
		for view in self.cpuContextViews.views:
			if view is None:
				continue
			if view.view_id in self.idbHookMap:
				entry = self.idbHookMap[view.view_id]
				view.setContent({"arch":entry.arch, "context":entry.cpu_ctx})

	def getAddressDetails(self, address):
		# FIXME: look for nearest .text, then get prev
		segm = get_prev_seg(address)
		moduleName = get_segm_name(segm)
		moduleBase = segm.startEA
		offset = address - moduleBase
		return (offset, moduleName)

	def handleQuickInstHook(self, address, once, breakpoint=False):
		# safety checks, can be start of the function
		if address in self.idbHookMap and self.idbHookMap[address].hook.type == "func":
			dlg = AskYN(0, "Address contains function hook!\nDo you want to remove it?")
			if dlg != 1:
				return
			# remove function hook
			self.handleUnhookFunc(address)

		offset, moduleName = self.getAddressDetails(address)

		hook = InstHook()
		hook.id = address
		hook.mnemonic = GetDisasm(address)
		hook.address = offset
		hook.module = moduleName
		hook.once = once
		hook.breakpoint = breakpoint

		entry = HookEntry(hook)
		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		SetColor(address, CIC_ITEM, kIDAViewColor_HookedInst)
		refresh_idaview_anyway()
		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.idbHookMap[address] = entry		

		self.idbHooksView.setContent(self.idbHookMap)

	def handleHookInstOnce(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		self.handleQuickInstHook(address, True)

	def handleHookInstPerm(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		self.handleQuickInstHook(address, False)

	def handleHookInstBreakOnce(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		self.handleQuickInstHook(address, True, True)

	def handleHookInstBreakPerm(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		self.handleQuickInstHook(address, False, True)

	def handleHookInstCust(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		# safety checks, can be start of the function
		if address in self.idbHookMap and self.idbHookMap[address].hook.type == "func":
			dlg = AskYN(0, "Address contains function hook!\nDo you want to remove it?")
			if dlg != 1:
				return
			# remove function hook
			self.handleUnhookFunc(address)

		offset, moduleName = self.getAddressDetails(address)

		hookDlg = InstructionHookDialog(moduleName, "%X" % address, GetDisasm(address), None)
		hookDlg.Compile()
		hookDlg.script.value = ""
		ok = hookDlg.Execute()
		if ok != 1:
			return

		hook = InstHook()
		hook.id = address
		hook.mnemonic = GetDisasm(address)
		hook.address = offset
		hook.module = moduleName
		hook.once = True if hookDlg.trigger.value == 0 else False
		hook.recentScriptFile = hookDlg.recentScriptFile
		hook.script = hookDlg.script.value

		entry = HookEntry(hook)
		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		SetColor(address, CIC_ITEM, kIDAViewColor_HookedInst)
		refresh_idaview_anyway()
		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.idbHookMap[address] = entry

		self.idbHooksView.setContent(self.idbHookMap)

	def handleQuickFuncHook(self, address, once):
		# safety checks, can be start of the function
		if address in self.idbHookMap and self.idbHookMap[address].hook.type == "inst":
			dlg = AskYN(0, "Address contains instruction hook!\nDo you want to remove it?")
			if dlg != 1:
				return
			# remove instruction hook
			self.handleUnhookInst(address)

		offset, moduleName = self.getAddressDetails(address)

		hook = FuncHook()
		hook.id = address
		hook.symbol = get_func_name(address)
		hook.address = offset
		hook.module = moduleName
		hook.once = once

		entry = HookEntry(hook)
		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		SetColor(address, CIC_FUNC, kIDAViewColor_HookedFunc)
		refresh_idaview_anyway()
		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.idbHookMap[address] = entry

		self.idbHooksView.setContent(self.idbHookMap)

	def handleHookFuncOnce(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())

		if func is None:
			return

		address = func.startEA;
		self.handleQuickFuncHook(address, True)

	def handleHookFuncPerm(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		address = func.startEA;
		self.handleQuickFuncHook(address, False)

	def handleHookFuncCust(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		address = func.startEA;

		# safety checks, can be start of the function
		if address in self.idbHookMap and self.idbHookMap[address].hook.type == "inst":
			dlg = AskYN(0, "Address contains instruction hook!\nDo you want to remove it?")
			if dlg != 1:
				return
			# remove instruction hook
			self.handleUnhookInst(address)

		offset, moduleName = self.getAddressDetails(address)

		hookDlg = FunctionHookDialog(moduleName, "%X" % address, get_func_name(address), None, None)
		hookDlg.Compile()
		hookDlg.script_enter.value = ""
		hookDlg.script_leave.value = ""
		ok = hookDlg.Execute()
		if ok != 1:
			return

		hook = FuncHook()
		hook.id = address
		hook.symbol = get_func_name(address)
		hook.address = offset
		hook.module = moduleName
		hook.once = True if hookDlg.trigger.value == 0 else False
		hook.enterRecentSrcFile = hookDlg.recentScriptFileEnter
		hook.enterScript = hookDlg.script_enter.value
		hook.leaveRecentSrcFile = hookDlg.recentScriptFileLeave
		hook.leaveScript = hookDlg.script_leave.value

		entry = HookEntry(hook)
		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		SetColor(address, CIC_FUNC, kIDAViewColor_HookedFunc)
		refresh_idaview_anyway()
		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.idbHookMap[address] = entry

		self.idbHooksView.setContent(self.idbHookMap)

	def handleHookInstEdit(self, screenEA = None):
		if self.hookedInstruction() == False:
			return
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()
		entry = self.idbHookMap[address]
		entry.hook.mnemonic = GetDisasm(address)

		hookDlg = InstructionHookDialog(entry.hook.module, "%X" % entry.hook.id, entry.hook.mnemonic, entry.hook.recentSrcFile)
		hookDlg.Compile()
		hookDlg.script.value = entry.hook.script
		hookDlg.trigger.value = 0 if entry.hook.once == True else 1
		ok = hookDlg.Execute()
		if ok != 1:
			return

		flags = HookEntry.UDP_NONE
		once = True if hookDlg.trigger.value == 0 else False
		if entry.hook.once != once:
			entry.hook.once = once
			flags |= HookEntry.UPD_TRIGGER

		entry.hook.recentSrcFile = hookDlg.recentScriptFile
		if entry.hook.script != hookDlg.script.value:
			entry.hook.script = hookDlg.script.value
			flags |= HookEntry.UPD_SCRIPT

		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(flags)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleHookFuncEdit(self, screenEA = None):
		if self.hookedFunction() == False:
			return
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		address = func.startEA;
		entry = self.idbHookMap[address]
		entry.hook.symbol = get_func_name(address)

		hookDlg = FunctionHookDialog(entry.hook.module, "%X" % entry.hook.id, entry.hook.symbol, entry.hook.enterRecentSrcFile, entry.hook.leaveRecentSrcFile)
		hookDlg.Compile()
		hookDlg.script_enter.value = entry.hook.enterScript
		hookDlg.script_leave.value = entry.hook.leaveScript
		hookDlg.trigger.value = 0 if entry.hook.once == True else 1
		ok = hookDlg.Execute()
		if ok != 1:
			return

		flags = HookEntry.UDP_NONE
		once = True if hookDlg.trigger.value == 0 else False
		if entry.hook.once != once:
			entry.hook.once = once
			flags |= HookEntry.UPD_TRIGGER

		entry.hook.enterRecentSrcFile = hookDlg.recentScriptFileEnter
		if entry.hook.enterScript != hookDlg.script_enter.value:
			entry.hook.enterScript = hookDlg.script_enter.value
			flags |= HookEntry.UPD_SCRIPT

		entry.hook.leaveRecentSrcFile = hookDlg.recentScriptFileLeave
		if entry.hook.leaveScript != hookDlg.script_leave.value:
			entry.hook.leaveScript = hookDlg.script_leave.value
			flags |= HookEntry.UPD_SCRIPT

		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(flags)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleHookInstShowCPU(self):
		if self.hookedInstruction() == False:
			return
		address = ScreenEA()
		if self.cpuContextViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = CPUContextView(self, entry.hook.id, entry.hook.mnemonic)
			self.cpuContextViews.addView("CPU Context", newView)
			self.cpuContextViews.setContent(entry.hook.id, {"arch":entry.arch, "context":entry.cpu_ctx})
		self.cpuContextViews.showView(address)

	def handleHookInstShowStack(self):
		if self.hookedInstruction() == False:
			return
		address = ScreenEA()
		if self.stackViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = StackView(self, entry.hook.id, entry.hook.mnemonic)
			self.stackViews.addView("Stack", newView)
			self.stackViews.setContent(entry.hook.id, entry.stack)
		self.stackViews.showView(address)

	def handleHookInstShowBacktrace(self):
		if self.hookedInstruction() == False:
			return
		address = ScreenEA()
		if self.backtraceViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = BacktraceView(self, entry.hook.id)
			self.backtraceViews.addView("Backtrace", newView)
			self.backtraceViews.setContent(entry.hook.id, entry.backtrace)
		self.backtraceViews.showView(address)

	def handleHookFuncShowCPU(self):
		if self.hookedFunction() == False:
			return

		func = get_func(ScreenEA())
		if func is None:
			return
		
		address = func.startEA;
		if self.cpuContextViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = CPUContextView(self, entry.hook.id, entry.hook.symbol)
			self.cpuContextViews.addView("CPU Context", newView)
			self.cpuContextViews.setContent(entry.hook.id, {"arch":entry.arch, "context":entry.cpu_ctx})
		self.cpuContextViews.showView(address)

	def handleHookFuncShowStack(self):
		if self.hookedFunction() == False:
			return

		func = get_func(ScreenEA())
		if func is None:
			return
		
		address = func.startEA;
		if self.stackViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = StackView(self, entry.hook.id, entry.hook.symbol)
			self.stackViews.addView("Stack", newView)
			self.stackViews.setContent(entry.hook.id, entry.stack)
		self.stackViews.showView(address)

	def handleHookFuncShowBacktrace(self):
		if self.hookedFunction() == False:
			return

		func = get_func(ScreenEA())
		if func is None:
			return
		
		address = func.startEA;
		if self.backtraceViews.hasView(address) == False:
			entry = self.idbHookMap[address]
			newView = BacktraceView(self, entry.hook.id)
			self.backtraceViews.addView("Backtrace", newView)
			self.backtraceViews.setContent(entry.hook.id, entry.backtrace)
		self.backtraceViews.showView(address)

	def handleHookInstLinkMemory(self):
		if self.hookedInstruction() == False:
			return
		address = ScreenEA()
		self.idbHookMap[address].mem_list = self.linkMemoryRanges();
		entry = self.idbHookMap[address]
		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(HookEntry.UPD_MEMLIST)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleHookFuncLinkMemory(self):
		if self.hookedFunction() == False:
			return

		func = get_func(ScreenEA())
		if func is None:
			return
		
		address = func.startEA;
		self.idbHookMap[address].mem_list = self.linkMemoryRanges();
		entry = self.idbHookMap[address]
		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(HookEntry.UPD_MEMLIST)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleMemoryRemoval(self, mem_id):
		for key in self.idbHookMap:
			entry = self.idbHookMap[key]
			if mem_id in entry.mem_list:
				entry.mem_list.remove(mem_id)
				if self.clientSocket is not None:
					outJSON = json.dumps({
						"req_id": kFridaLink_UpdHookRequest, 
						"data": entry.genUpdRequest(HookEntry.UPD_MEMLIST)
					}) 
					self.clientSocket.sendto(outJSON, self.clientAddress)


	def handleUnhookInst(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()

		if self.hookedInstruction(address) == False:
			return

		entry = self.idbHookMap[address]
		outJSON = json.dumps({
			"req_id": kFridaLink_DelHookRequest, 
			"data": entry.genDelRequest()
		})

		del self.idbHookMap[address]
		self.clientSocket.sendto(outJSON, self.clientAddress)
		SetColor(address, CIC_ITEM, kIDAViewColor_Reset)
		refresh_idaview_anyway()

		self.idbHooksView.setContent(self.idbHookMap)

	def handleUnhookFunc(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())
		if func is None:
			return

		address = func.startEA;
		if self.hookedFunction(address) == False:
			return
		
		entry = self.idbHookMap[address]
		outJSON = json.dumps({
			"req_id": kFridaLink_DelHookRequest, 
			"data": entry.genDelRequest()
		})

		del self.idbHookMap[address]
		self.clientSocket.sendto(outJSON, self.clientAddress)
		SetColor(address, CIC_FUNC, kIDAViewColor_Reset)
		refresh_idaview_anyway()

		self.idbHooksView.setContent(self.idbHookMap)

	def showDatabaseHooks(self):
		self.idbHooksView.setContent(self.idbHookMap)
		self.idbHooksView.show()

	def showArbitraryHooks(self):
		print "FridaLink: arbitrary hooks are not implemented yet\n"
		# hookDlg = ArbitraryHookDialog(self.getModuleNamesList(), None, None)
		# hookDlg.Compile()
		# hookDlg.Execute()

	def addArbitraryHook(self, hook_id):
		print "FridaLink: arbitrary hooks are not implemented yet\n"

	def delArbitraryHook(self, hook_id):
		print "FridaLink: arbitrary hooks are not implemented yet\n"

	def editArbitraryHook(self, hook_id):
		print "FridaLink: arbitrary hooks are not implemented yet\n"

	def handleHookImportSymbolForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		# if symbol already hooked, open edit dialog
		if importEntry.address in self.importHookMap:
			self.handleEditImportSymbolHook(importEntry.address)
			return

		hookDlg = FunctionHookDialog(os.path.basename(importEntry.module), "%X" % importEntry.address, importEntry.symbol, None, None)
		hookDlg.Compile()
		hookDlg.script_enter.value = ""
		hookDlg.script_leave.value = ""
		ok = hookDlg.Execute()
		if ok != 1:
			return

		hook = FuncHook()
		hook.id = importEntry.address
		hook.symbol = importEntry.symbol
		hook.address = importEntry.address
		hook.module = os.path.basename(importEntry.module)
		hook.once = True if hookDlg.trigger.value == 0 else False
		hook.moduleImport = True
		hook.enterRecentSrcFile = hookDlg.recentScriptFileEnter
		hook.enterScript = hookDlg.script_enter.value
		hook.leaveRecentSrcFile = hookDlg.recentScriptFileLeave
		hook.leaveScript = hookDlg.script_leave.value

		entry = HookEntry(hook)
		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.importHookMap[importEntry.address] = entry

		self.importHooksView.setContent(self.importHookMap)		

	def showImportSymbolCPUForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		address = importEntry.address;
		if self.cpuContextViews.hasView(address) == False:
			entry = self.importHookMap[address]
			newView = CPUContextView(self, entry.hook.id, entry.hook.symbol)
			self.cpuContextViews.addView("CPU Context", newView)
			self.cpuContextViews.setContent(entry.hook.id, {"arch":entry.arch, "context":entry.cpu_ctx})
		self.cpuContextViews.showView(address)

	def showImportSymbolStackForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		address = importEntry.address;
		if self.stackViews.hasView(address) == False:
			entry = self.importHookMap[address]
			newView = StackView(self, entry.hook.id, entry.hook.symbol)
			self.stackViews.addView("Stack", newView)
			self.stackViews.setContent(entry.hook.id, entry.stack)
		self.stackViews.showView(address)

	def shoeImportSymbolBacktraceForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		address = importEntry.address;
		if self.backtraceViews.hasView(address) == False:
			entry = self.importHookMap[address]
			newView = BacktraceView(self, entry.hook.id)
			self.backtraceViews.addView("Backtrace", newView)
			self.backtraceViews.setContent(entry.hook.id, entry.backtrace)
		self.backtraceViews.showView(address)

	def handleLinkmemImportSymbolForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		address = importEntry.address;
		self.importHookMap[address].mem_list = self.linkMemoryRanges();
		entry = self.importHookMap[address]
		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(HookEntry.UPD_MEMLIST)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def handleEditImportSymbolForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		self.handleEditImportSymbolHook(importEntry.address)

	def handleUnhookImportSymbolForIdx(self, import_idx):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		importEntry = self.imports[import_idx]

		if importEntry.address not in self.importHookMap:
			return

		self.handleUnhookImportSymbol(importEntry.address)

	def handleUnhookImportSymbol(self, hook_id):
		if hook_id not in self.importHookMap:
			return

		entry = self.importHookMap[hook_id]

		outJSON = json.dumps({
			"req_id": kFridaLink_DelHookRequest, 
			"data": entry.genDelRequest()
		})

		del self.importHookMap[hook_id]
		self.clientSocket.sendto(outJSON, self.clientAddress)

		self.importHooksView.setContent(self.importHookMap)

	def handleEditImportSymbolHook(self, hook_id):
		if hook_id not in self.importHookMap:
			return

		entry = self.importHookMap[hook_id]

		hookDlg = FunctionHookDialog(entry.hook.module, "%X" % entry.hook.id, entry.hook.symbol, entry.hook.enterRecentSrcFile, entry.hook.leaveRecentSrcFile)
		hookDlg.Compile()
		hookDlg.script_enter.value = entry.hook.enterScript
		hookDlg.script_leave.value = entry.hook.leaveScript
		hookDlg.trigger.value = 0 if entry.hook.once == True else 1
		ok = hookDlg.Execute()
		if ok != 1:
			return

		flags = HookEntry.UDP_NONE
		once = True if hookDlg.trigger.value == 0 else False
		if entry.hook.once != once:
			entry.hook.once = once
			flags |= HookEntry.UPD_TRIGGER

		entry.hook.enterRecentSrcFile = hookDlg.recentScriptFileEnter
		if entry.hook.enterScript != hookDlg.script_enter.value:
			entry.hook.enterScript = hookDlg.script_enter.value
			flags |= HookEntry.UPD_SCRIPT

		entry.hook.leaveRecentSrcFile = hookDlg.recentScriptFileLeave
		if entry.hook.leaveScript != hookDlg.script_leave.value:
			entry.hook.leaveScript = hookDlg.script_leave.value
			flags |= HookEntry.UPD_SCRIPT

		outJSON = json.dumps({
			"req_id": kFridaLink_UpdHookRequest, 
			"data": entry.genUpdRequest(flags)
		}) 
		self.clientSocket.sendto(outJSON, self.clientAddress)

	def showImportHooks(self):
		self.importHooksView.setContent(self.importHookMap)
		self.importHooksView.show()

	def handleHookResponse(self, platform, arch, response):
		hook_id = int(response['id'], 16)
		if hook_id in self.idbHookMap:
			entry = self.idbHookMap[hook_id]
		elif hook_id in self.importHookMap:
			entry = self.importHookMap[hook_id]
		# unable to install hook
		if response['count'] == 0:
			if entry.hook.type == "inst":
				del self.idbHookMap[hook_id]
				SetColor(hook_id, CIC_ITEM, kIDAViewColor_Reset)
				refresh_idaview_anyway()
			elif entry.hook.type == "func":
				if entry.hook.moduleImport == False:
					del self.idbHookMap[hook_id]
					SetColor(hook_id, CIC_FUNC, kIDAViewColor_Reset)
					refresh_idaview_anyway()
					return
				else:
					del self.importHookMap[hook_id]
					return

		# get backtrace and CPU context
		entry.setResponse(platform, arch, response)
		# get memory dumps
		for memory in response['memory']:
			self.updateMemoryContent(memory['mem_id'], memory['content'])
		# update backtrace content
		entry.backtrace = self.processBacktrace(entry.backtrace)
		if self.backtraceViews.hasView(entry.hook.id) == True:
			self.backtraceViews.setContent(entry.hook.id, entry.backtrace)
		# update CPU context content
		if self.cpuContextViews.hasView(entry.hook.id) == True:
			self.cpuContextViews.setContent(entry.hook.id, {"arch":entry.arch, "context":entry.cpu_ctx})
		# update stack content
		if self.stackViews.hasView(entry.hook.id) == True:
			self.stackViews.setContent(entry.hook.id, entry.stack)
		# remove hook if 'once'
		if entry.hook.once == True:
			if entry.hook.type == "inst":
				if entry.hook.breakpoint == True:
					self.debugBreakId = hook_id
					SetColor(hook_id, CIC_ITEM, kIDAViewColor_Break)
				else:
					SetColor(hook_id, CIC_ITEM, kIDAViewColor_Reset)
				del self.idbHookMap[hook_id]
				refresh_idaview_anyway()
				self.idbHooksView.setContent(self.importHookMap)
			elif entry.hook.type == "func":
				if entry.hook.moduleImport == False:
					SetColor(hook_id, CIC_FUNC, kIDAViewColor_Reset)
					del self.idbHookMap[hook_id]
					refresh_idaview_anyway()
					self.idbHooksView.setContent(self.importHookMap)
				else:
					del self.importHookMap[hook_id]
					self.importHooksView.setContent(self.importHookMap)
		elif entry.hook.type == "inst" and entry.hook.breakpoint == True:
			self.debugBreakId = hook_id
			SetColor(hook_id, CIC_ITEM, kIDAViewColor_Break)
			refresh_idaview_anyway()

	def hookedInstruction(self, screenEA = None):
		if screenEA is not None:
			address = screenEA
		else:
			address = ScreenEA()
		if address in self.idbHookMap:
			# can be start of the function, check hook type
			if self.idbHookMap[address].hook.type == "inst":
				return True
			else:
				return False
		else:
			return False

	def hookedFunction(self, screenEA = None):
		if screenEA is not None:
			func = get_func(screenEA)
		else:
			func = get_func(ScreenEA())

		if func is None:
			return False;

		address = func.startEA;
		if address in self.idbHookMap:
			# can be start of the function, check hook type
			if self.idbHookMap[func.startEA].hook.type == "func":
				return True
			else:
				return False
		else:
			return False

	def cpuViewClosed(self, view_id):
		self.cpuContextViews.delView(view_id)

__all__ = [
    'HookEngineProtocol'
]
