#
#  BacktraceEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import get_segm_by_name, get_func, get_func_name
from idc import AskYN

from ..Core.Modules import LoadModule
from ..UI.ViewStore import ViewStore
from ..Core.Types import Backtrace
from ..Settings.SettingsStorage import SettingsStorage as FrLSettings

from ..Utils.Logging import fl_log

class BacktraceEngineProtocol(object):

	def __init__(self):
		super(BacktraceEngineProtocol, self).__init__()
		self.backtraceViews = ViewStore()

	def delBacktraceView(self, view_id):
		self.backtraceViews.delView(view_id)

	def processBacktrace(self, backtrace):
		ignoreModules = []
		for idx in range(backtrace.getCount()):
			entry = backtrace.getEntry(idx)
			if entry is None:
				continue
			# skip bad entries
			if entry.mod_base == 0:
				continue
			if entry.sym_name == '' or entry.sym_name == '<redacted>':
				# reveal unknown symbols
				mod_name = str(entry.mod_name).replace(' ', '_')
				mod_base = entry.mod_base
				segm = get_segm_by_name(mod_name)
				name = "unknown"
				addr = 0
				idb_addr = False
				if segm is None:
					if backtrace.platform != "unknown":
						if mod_name not in ignoreModules:
							dlg = AskYN(0, "Do you want to load module '" + mod_name + "'?\n" + 
								"Note that depends on module size this may take a while.")
							if dlg == 1: # YES
								mod_path = str(entry.mod_path)
								LoadModule(backtrace.platform, mod_name, mod_path)
								# rebuild import table
								self.handleBuildImport()
							elif dlg == 0: # NO
								ignoreModules.append(mod_name)
							# dlg == -1: CANCEL

						segm = get_segm_by_name(mod_name)
				if segm is not None:
					seg_base = segm.startEA
					call = entry.sym_call - mod_base + seg_base
					func = get_func(call)
					if func is not None:
						name = get_func_name(call)
						addr = func.startEA
					idb_addr = True
				else:
					addr = mod_base
					call = entry.sym_call

				backtrace.entries[idx].sym_addr = addr
				backtrace.entries[idx].sym_name = name
				backtrace.entries[idx].sym_call = call
				backtrace.entries[idx].idb_addr = idb_addr
			elif FrLSettings().getOverwriteSymbolName():
				# update symbol from IDA database if it exists
				mod_name = str(entry.mod_name)
				mod_base = entry.mod_base
				segm = get_segm_by_name(mod_name)
				if segm is not None:
					seg_base = segm.startEA
					call = entry.sym_call - mod_base + seg_base
					func = get_func(call)
					if func is not None:
						name = get_func_name(call)
						addr = func.startEA
						backtrace.entries[idx].sym_addr = addr
						backtrace.entries[idx].sym_name = name
						backtrace.entries[idx].sym_call = call
		return backtrace

	def handleBacktraceRequest(self, platfrom, arch, data):
		backtrace = Backtrace(platfrom, arch, data)
		return self.processBacktrace(backtrace).getArray()

	def backtraceViewClosed(self, view_id):
		self.backtraceViews.delView(view_id)

__all__ = [
    'BacktraceEngineProtocol'
]
