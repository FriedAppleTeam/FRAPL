#
#  DebugEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import json

import idaapi
from idaapi import refresh_idaview_anyway
from idaapi import decode_insn, getFlags
from idc import SetColor, CIC_ITEM
from idc import isCode, GetDisasm

from ..Core.Types import InstHook, HookEntry

from ..UI.Colors import *
from ..Utils.Logging import fl_log as fl_log

from ..Common.MessageTypes import *

class DebugEngineProtocol(object):

	def __init__(self):
		super(DebugEngineProtocol, self).__init__()
		self.debugBreakId = None

	def resetBreakColors(self):
		if self.debugBreakId != None:
			SetColor(self.debugBreakId, CIC_ITEM, kIDAViewColor_Reset)

	def handleDebugContinue(self):
		if self.clientSocket is None:
			return

		if self.debugBreakId is None:
			return
			
		outJSON = json.dumps({
			"req_id": kFridaLink_DebugContinue, 
		})
		self.clientSocket.sendto(outJSON, self.clientAddress)

		if self.debugBreakId in self.idbHookMap:
			SetColor(self.debugBreakId, CIC_ITEM, kIDAViewColor_HookedInst)
		else:
			SetColor(self.debugBreakId, CIC_ITEM, kIDAViewColor_Reset)

		refresh_idaview_anyway()
		self.debugBreakId = None

	def handleDebugStepInto(self):
		if self.clientSocket is None:
			return

		if self.debugBreakId is None:
			return

		fr_log("FridaLink: Debug step into not implemented\n")

	def handleDebugStepOver(self):
		if self.clientSocket is None:
			return

		if self.debugBreakId is None:
			return

		cur_ea = self.debugBreakId
		decode_insn(cur_ea)
		next_ea = cur_ea + idaapi.cmd.size

		if isCode(getFlags(next_ea)) == False:
			return

		entry = None
		# remove current 
		if self.debugBreakId in self.idbHookMap:
			entry = self.idbHookMap[self.debugBreakId]
			outJSON = json.dumps({
				"req_id": kFridaLink_DelHookRequest, 
				"data": entry.genDelRequest()
			})

			del self.idbHookMap[self.debugBreakId]
			self.clientSocket.sendto(outJSON, self.clientAddress)
			SetColor(self.debugBreakId, CIC_ITEM, kIDAViewColor_Reset)
			refresh_idaview_anyway()

		offset, moduleName = self.getAddressDetails(next_ea)

		# install next
		if entry == None:
			hook = InstHook()
			hook.id = next_ea
			hook.once = once
			hook.breakpoint = True
			entry = HookEntry(hook)

		entry.hook.id = next_ea
		entry.hook.mnemonic = GetDisasm(next_ea)
		entry.hook.address = offset
		entry.hook.module = moduleName

		outJSON = json.dumps({
			"req_id": kFridaLink_SetHookRequest, 
			"data": entry.genSetRequest()
		})

		self.clientSocket.sendto(outJSON, self.clientAddress)
		self.idbHookMap[next_ea] = entry		

		self.idbHooksView.setContent(self.idbHookMap)
		
		self.handleDebugContinue()

__all__ = [
    'DebugEngineProtocol'
]
