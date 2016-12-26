#
#  IdaEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import os

from idaapi import get_import_module_qty, get_import_module_name, enum_import_names
from idaapi import getn_func, get_segm_by_name

from ..Core.Modules import LoadModule
from ..Core.Types import ImportEntry

from ..UI.Actions import *
from ..Utils.Logging import fl_log as fl_log

class IdaEngineProtocol(object):
	def __init__(self):
		super(IdaEngineProtocol, self).__init__()
		self.imports = []
		self.currentModuleName = None

	def imports_names_cb(self, ea, name, ord):
		self.imports.append(ImportEntry(self.currentModuleName, ea, name))
		# continue enumeration
		return True

	def handleBuildImport(self):
		nimps = get_import_module_qty()

		self.imports = []

		for i in xrange(0, nimps):
			self.currentModuleName = get_import_module_name(i)
			if not self.currentModuleName:
				continue

			enum_import_names(i, self.imports_names_cb)

	def handleLoadImportModule(self, index):
		if self.targetPlatform is None:
			return

		path = self.imports[index].module
		LoadModule(self.getTargetPlatform(), os.path.basename(path), path)

	def handleIdaViewMenuAction(self, actionType):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		actionHandlers = {
			# HOOKS
			kPopupAction_HookInstOnce 		: self.handleHookInstOnce,
			kPopupAction_HookInstPerm 		: self.handleHookInstPerm,
			kPopupAction_HookInstBreakOnce	: self.handleHookInstBreakOnce,
			kPopupAction_HookInstBreakPerm	: self.handleHookInstBreakPerm,
			kPopupAction_HookInstCust 		: self.handleHookInstCust,
			kPopupAction_HookFuncOnce 		: self.handleHookFuncOnce,
			kPopupAction_HookFuncPerm 		: self.handleHookFuncPerm,
			kPopupAction_HookFuncCust 		: self.handleHookFuncCust,
			kPopupAction_HookInstEdit 		: self.handleHookInstEdit,
			kPopupAction_HookFuncEdit 		: self.handleHookFuncEdit,
			kPopupAction_HookInstCPU  		: self.handleHookInstShowCPU,
			kPopupAction_HookFuncCPU		: self.handleHookFuncShowCPU,
			kPopupAction_HookInstStack		: self.handleHookInstShowStack,
			kPopupAction_HookFuncStack		: self.handleHookFuncShowStack,
			kPopupAction_HookInstBacktrace  : self.handleHookInstShowBacktrace,
			kPopupAction_HookFuncBacktrace  : self.handleHookFuncShowBacktrace,
			kPopupAction_HookInstLinkMem  	: self.handleHookInstLinkMemory,
			kPopupAction_HookFuncLinkMem  	: self.handleHookFuncLinkMemory,
			kPopupAction_UnhookInst   		: self.handleUnhookInst,
			kPopupAction_UnhookFunc   		: self.handleUnhookFunc,
			# REPLACE
			kPopupAction_ReplaceFunc        : self.handleReplaceFunc,
			kPopupAction_ReplaceFuncEdit    : self.handleReplaceFuncEdit,
			kPopupAction_ReplaceFuncDel     : self.handleReplaceFuncDel,
			# MISC
			kPopupAction_GetRealAddress		: self.handleGetRealAddress,
		}

		actionHandlers[actionType]()

	def handleFuncViewMenuAction(self, actionType, index):
		if self.clientSocket is None:
			fl_log("FridaLink: Frida not connected\n");
			return

		actionHandlers = {
			# HOOKS
			kPopupAction_HookFuncOnce 		: self.handleHookFuncOnce,
			kPopupAction_HookFuncPerm 		: self.handleHookFuncPerm,
			kPopupAction_HookFuncCust 		: self.handleHookFuncCust,
			kPopupAction_HookFuncEdit 		: self.handleHookFuncEdit,
			kPopupAction_HookFuncCPU		: self.handleHookFuncShowCPU,
			kPopupAction_HookFuncStack		: self.handleHookFuncShowStack,
			kPopupAction_HookFuncBacktrace  : self.handleHookFuncShowBacktrace,
			kPopupAction_HookFuncLinkMem  	: self.handleHookFuncLinkMemory,
			kPopupAction_UnhookFunc   		: self.handleUnhookFunc,
			# REPLACE
			kPopupAction_ReplaceFunc        : self.handleReplaceFunc,
			kPopupAction_ReplaceFuncEdit    : self.handleReplaceFuncEdit,
			kPopupAction_ReplaceFuncDel     : self.handleReplaceFuncDel,
		}

		actionHandlers[actionType](getn_func(index).startEA)

	def handleImportViewMenuAction(self, actionType, index):
		# if self.clientSocket is None:
		# 	fl_log("FridaLink: Frida not connected\n");
		# 	return

		actionHandlers = {
			kPopupAction_HookImportSymbol		: self.handleHookImportSymbolForIdx,
			kPopupAction_HookImpSymbolCPU       : self.showImportSymbolCPUForIdx,
			kPopupAction_HookImpSymbolStack     : self.showImportSymbolStackForIdx,
			kPopupAction_HookImpSymbolBacktrace : self.shoeImportSymbolBacktraceForIdx,
			kPopupAction_HookImpSymbolLinkMem   : self.handleLinkmemImportSymbolForIdx,
			kPopupAction_HookImpSymbolEdit      : self.handleEditImportSymbolForIdx,
			kPopupAction_UnhookImpSymbol        : self.handleUnhookImportSymbolForIdx,
			kPopupAction_ReplaceImportSymbol 	: self.handleReplaceImportSymbolForIdx,
			kPopupAction_LoadImportModule 	    : self.handleLoadImportModule,
		}

		actionHandlers[actionType](index)

	def getIdbModuleBase(self, module):
		segm = get_segm_by_name(str(module).replace(' ', '_'))
		return segm.startEA

__all__ = [
    'IdaEngineProtocol'
]
