#
#  FridaLink.py
#  FridaLink IDA  
#
#  Created by Alexander Hude on 16/11/15.
#  Copyright (c) 2015 FriedApple. All rights reserved.
#

import SocketServer
import threading
import pickle
import select
import socket
import json

# IDA Python SDK
from idaapi import *
from idc import *

# FridaLink modules

import FridaLink.Common.Config
import FridaLink.Utils.Logging
import FridaLink.Core.Modules as FrLModules
import FridaLink.UI.MainMenu as IdaMainMenu
import FridaLink.UI.PopupMenus as IdaPopupMenus
import FridaLink.UI.SettingsDialog

import FridaLink.Core.IdaEngine
import FridaLink.Core.FridaEngine
import FridaLink.Core.BacktraceEngine
import FridaLink.Core.HookEngine
import FridaLink.Core.ReplaceImplEngine
import FridaLink.Core.MemoryEngine
import FridaLink.Core.DebugEngine
import FridaLink.Core.AppLogEngine
import FridaLink.DB.DBProtocol

# Load current FridaLink config and settings
reload(FridaLink.Common.Config)
reload(FridaLink.Settings.SettingsStorage)

# Reload modules in debug mode
if FridaLink.Common.Config.DevModeEnabled() == True:
	reload(FridaLink.Utils.Logging)
	reload(FridaLink.Core.Modules)
	reload(FridaLink.UI.MainMenu)
	reload(FridaLink.UI.PopupMenus)
	reload(FridaLink.UI.SettingsDialog)
	reload(FridaLink.Core.IdaEngine)
	reload(FridaLink.Core.FridaEngine)
	reload(FridaLink.Core.BacktraceEngine)
	reload(FridaLink.Core.HookEngine)
	reload(FridaLink.Core.ReplaceImplEngine)
	reload(FridaLink.Core.MemoryEngine)
	reload(FridaLink.Core.DebugEngine)
	reload(FridaLink.Core.AppLogEngine)
	reload(FridaLink.DB.DBProtocol)

from FridaLink.Utils.Logging import fl_log as fl_log
from FridaLink.Settings.SettingsStorage import SettingsStorage as FrLSettings
from FridaLink.UI.SettingsDialog import SettingsDialog as FrLSettingsDlg
from FridaLink.UI.LoadModuleDialog import LoadModuleDialog as FrLLoadModuleDlg
from FridaLink.Common.MessageTypes import *

# *** CALLABLES

class TargetInfoCallable:
	def __init__(self, engine, platform, arch):
		self.engine = engine
		self.platform = platform
		self.arch = arch
	def __call__(self):
		self.request = self.engine.handleTargetInfo(self.platform, self.arch)

class ModulesResponseCallable:
	def __init__(self, engine, modules):
		self.engine = engine
		self.modules = modules
	def __call__(self):
		self.engine.handleModulesResponse(self.modules)

class BacktraceCallable:
	def __init__(self, engine, platform, arch, request):
		self.engine = engine
		self.platform = platform
		self.arch = arch
		self.request = request
	def __call__(self):
		self.request = self.engine.handleBacktraceRequest(self.platform, self.arch, self.request)

class HookCallable:
	def __init__(self, engine, platform, arch, response):
		self.engine = engine
		self.platform = platform
		self.arch = arch
		self.response = response
	def __call__(self):
		self.engine.handleHookResponse(self.platform, self.arch, self.response)

class ReplaceCallable:
	def __init__(self, engine, response):
		self.engine = engine
		self.response = response
	def __call__(self):
		self.engine.handleReplaceResponse(self.response)

class MemoryCallable:
	def __init__(self, engine, platform, arch, response):
		self.engine = engine
		self.platform = platform
		self.arch = arch
		self.response = response
	def __call__(self):
		self.engine.handleMemoryFetchResponse(self.platform, self.arch, self.response)

class FraplLogCallable:
	def __init__(self, engine, log_type, log_entry):
		self.engine = engine
		self.log_type = log_type
		self.log_entry = log_entry
	def __call__(self):
		self.engine.handleFraplLog(self.log_type, self.log_entry)

class TargetLogCallable:
	def __init__(self, engine, log_header, log_entry):
		self.engine = engine
		self.log_header = log_header
		self.log_entry = log_entry
	def __call__(self):
		self.engine.handleTargetLog(self.log_header, self.log_entry)

class QueryCallable:
	def __init__(self, engine, db_id, query):
		self.engine = engine
		self.db_id = db_id
		self.query = query
	def __call__(self):
		self.engine.handleDbQuery(self.db_id, self.query)

# *** TCP MESSAGE HANDLER

class MessageHandler(SocketServer.BaseRequestHandler):

	def sendAck(self):
		outJSON = json.dumps({
			"req_id": kFridaLink_Ack, 
		})
		self.request.sendto(outJSON, self.client_address)

	def handleFridaRequest(self, message):
		decoder = json.JSONDecoder()
		while message:
			try:
				inJSON, idx = decoder.raw_decode(message)
			except Exception as e:
				fl_log("FridaLink: unable to decode JSON message: %s\n-------%s\n-------\n" % (str(e), message))
				return
			
			if inJSON['req_id'] == kFridaLink_TargetInfo:
				targetInfo = TargetInfoCallable(self.server.engine, inJSON['platform'], inJSON['arch'])
				execute_sync(targetInfo, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_ModulesResponse:
				modules = ModulesResponseCallable(self.server.engine, inJSON['response'])
				execute_sync(modules, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_HookResponse:
				hook = HookCallable(self.server.engine, inJSON['platform'], inJSON['arch'], inJSON['response'])
				execute_sync(hook, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_ReplaceResponse:
				replace = ReplaceCallable(self.server.engine, inJSON['response'])
				execute_sync(replace, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_FetchMemResponse:
				hook = MemoryCallable(self.server.engine, inJSON['platform'], inJSON['arch'], inJSON['response'])
				execute_sync(hook, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_FraplLogEntry:
				fraplLog = FraplLogCallable(self.server.engine, inJSON['log_type'], inJSON['log_entry'])
				execute_sync(fraplLog, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_TargetLogEntry:
				targetLog = TargetLogCallable(self.server.engine, inJSON['log_header'], inJSON['log_entry'])
				execute_sync(targetLog, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_DBQuery:
				query = QueryCallable(self.server.engine, inJSON['db_id'], inJSON['query'])
				execute_sync(query, 0)
				self.sendAck()
			elif inJSON['req_id'] == kFridaLink_ProcessBacktrace:
				backtrace = BacktraceCallable(self.server.engine, inJSON['platform'], inJSON['arch'], inJSON['request'])
				execute_sync(backtrace, 0)
				outJSON = json.dumps({
					"req_id": kFridaLink_ProcessBacktrace, 
					"request": backtrace.request
				})
				self.request.sendto(outJSON, self.client_address)
			message = message[idx:].lstrip()            

	def handle(self):
		# allow only one FridaLink connection
		if self.server.engine.clientSocket is not None:
			return

		fl_log("FridaLink: established with " + str(self.client_address) + "\n")
		self.server.engine.clientSocket = self.request
		self.server.engine.clientAddress = self.client_address
		self.server.engine.clientConnected();        
		while True:
			header = self.request.recv(8)
			if not header:
				break
			try:
				dataLength = int(header)
			except Exception as e:
				fl_log("FridaLink: invalid header %s" % header)

			msg = ""
			while dataLength != 0:
				bytesToRead = dataLength if dataLength < 4096 else 4096
				data = self.request.recv(bytesToRead)
				msg += data
				dataLength -= bytesToRead

			self.handleFridaRequest(msg)

		self.server.engine.clientSocket = None
		self.server.engine.clientAddress = None
		fl_log("FridaLink: closed with " + str(self.client_address) + "\n")
		self.request.close()

# *** PLUGIN CLASS

class FridaLinkPlugin(	plugin_t,
						FridaLink.Core.IdaEngine.IdaEngineProtocol,
						FridaLink.Core.FridaEngine.FridaEngineProtocol,
						FridaLink.Core.BacktraceEngine.BacktraceEngineProtocol,
						FridaLink.Core.HookEngine.HookEngineProtocol,
						FridaLink.Core.ReplaceImplEngine.ReplaceImplEngineProtocol,
						FridaLink.Core.MemoryEngine.MemoryEngineProtocol,
						FridaLink.Core.DebugEngine.DebugEngineProtocol,
						FridaLink.Core.AppLogEngine.AppLogEngineProtocol,
						FridaLink.DB.DBProtocol.DBProtocol
					  ):

	flags = PLUGIN_KEEP
	comment = ""

	help = "Plugin That uses Frida API"
	wanted_name = "Frida Link"
	wanted_hotkey = ""

	def init(self):
		# FIXME: make init method for modules
		super(FridaLinkPlugin, self).__init__()
		fl_log("FridaLink: loaded\n")
		self.server = None
		self.serverThread = None 
		self.serverStopped = threading.Event()
		self.serverRunning = False

		self.clientSocket = None
		self.clientAddress = None
		return PLUGIN_KEEP

	def clientConnected(self):
		self.requestModules()
		self.syncMemoryRegions()
		self.deleteAllHooks()
		self.syncIdbHooks()
		self.syncImportHooks()
		self.deleteAllReplaced()
		self.syncReplacedFuncs();

	def run(self, arg):
		fl_log("FridaLink: run(%d)\n" % arg)

	def run(self, arg = 0):
		fl_log("FridaLink: run()\n")
		IdaMainMenu.RegisterMenuActions(self)
		IdaPopupMenus.RegisterMenuActions(self)
		self.handleBuildImport()
		self.startServer()

	def termThread(self):
		if self.clientSocket is not None:
			self.clientSocket.shutdown(socket.SHUT_RDWR)

		if self.serverRunning == True:
	 		self.server.shutdown()
	 		self.serverStopped.wait(3)
	 		self.serverThread = None

		fl_log("FridaLink: unloaded\n")

	def term(self):	# asynchronous unload (external, UI_Hook::term)

		# disable logging to prevert deadlocks
		FrLSettings().setLogEnabled(False);

		if self.clientSocket is not None:
			self.clientSocket.shutdown(socket.SHUT_RDWR)

		if self.serverRunning == True:
	 		self.server.shutdown()

	 	self.closeAllDBs();

		self.resetHookedColors();
		self.resetReplacedColors();

		IdaPopupMenus.UnregisterMenuActions()
		IdaMainMenu.UnregisterMenuActions()

		request_refresh(0xFFFFFFFF) # IWID_ALL

	def unloadPlugin(self):	# synchronous unload (internal, Main Menu)

		self.resetHookedColors();
		self.resetReplacedColors();

		IdaPopupMenus.UnregisterMenuActions()
		IdaMainMenu.UnregisterMenuActions()

		request_refresh(0xFFFFFFFF) # IWID_ALL

		# do not block UI while stopping server
		t = threading.Thread(target=self.termThread)
		t.start()

	def doNothing(self):
		pass

	def logToggle(self):
		if FrLSettings().getLogEnabled():
			fl_log("FridaLink: Debug Log disabled\n")
		FrLSettings().setLogEnabled(not FrLSettings().getLogEnabled())
		if FrLSettings().getLogEnabled():
			fl_log("FridaLink: Debug Log enabled\n")

	def loadModule(self):
		loadModuleDlg = FrLLoadModuleDlg()
		loadModuleDlg.Compile()
		loadModuleDlg.filePath.value = "*"
		ok = loadModuleDlg.Execute()
	
		if ok == 1:
			path = loadModuleDlg.filePath.value
			if path != "*":
				module = os.path.basename(path)
				FrLModules.LoadModule(None, module, path)
	
		loadModuleDlg.Free()

	def overwriteSymbolToggle(self):
		FrLSettings().setOverwriteSymbolName(not FrLSettings().getOverwriteSymbolName())
		if FrLSettings().getOverwriteSymbolName():
			fl_log("FridaLink: Symbol Overwrite enabled\n")
		else:
			fl_log("FridaLink: Symbol Overwrite disabled\n")

	def loadProject(self):
		if self.clientSocket == None:
			fl_log("FridaLink: Frida not connected\n");
			return

		filePath = AskFile(0, "*.flp", "Open FridaLink project")
		if filePath is None:
			return
		with open(filePath, 'rb') as file:
			settings = pickle.load(file)
			hooks = pickle.load(file)
			repl = pickle.load(file)
			memory = pickle.load(file)
			frida = pickle.load(file)

			FrLSettings().restore(settings)
			self.deleteAllHooks();
			self.deleteAllReplaced();
			self.restoreHookData(hooks)
			self.restoreReplacedFuncData(repl)
			self.restoreMemoryData(memory)
			self.restoreFridaData(frida)

			file.close()
			fl_log("FridaLink: project loaded\n")

	def saveProject(self):
		filePath = AskFile(1, "*.flp", "Save FridaLink project")
		if filePath is None:
			return
		with open(filePath, 'wb') as file:
			pickle.dump(FrLSettings(), file, pickle.HIGHEST_PROTOCOL)
			pickle.dump(self.backupHookData(), file, pickle.HIGHEST_PROTOCOL)
			pickle.dump(self.backupReplacedFuncData(), file, pickle.HIGHEST_PROTOCOL)
			pickle.dump(self.backupMemoryData(), file, pickle.HIGHEST_PROTOCOL)
			pickle.dump(self.backupFridaData(), file, pickle.HIGHEST_PROTOCOL)
			file.close()
			fl_log("FridaLink: project saved\n")

	def showSettings(self):
		settingsDlg = FrLSettingsDlg()
		settingsDlg.Compile()
		settingsDlg.host.value = FrLSettings().getHost()
		settingsDlg.port.value = FrLSettings().getPort()
		settingsDlg.cpuctx_cols.value = FrLSettings().getCpuContextColumns()
		ok = settingsDlg.Execute()
		if ok == 1:
			FrLSettings().setHost(settingsDlg.host.value)
			FrLSettings().setPort(settingsDlg.port.value)
			if FrLSettings().getCpuContextColumns() != settingsDlg.cpuctx_cols.value:
				FrLSettings().setCpuContextColumns(settingsDlg.cpuctx_cols.value)
				self.refreshCpuViews()

	def serverTask(self):
		try:
			self.server = SocketServer.ThreadingTCPServer(
				(FrLSettings().getHost(), FrLSettings().getPort()), 
				MessageHandler
			)
			self.server.engine = self
	
			fl_log("FridaLink: SERVER STARTED!\n")

			self.serverStopped.clear()
			self.serverRunning = True
			self.server.serve_forever()
			self.serverRunning = False

			self.server.server_close()
			self.server = None

			fl_log("FridaLink: SERVER STOPPED!\n")
			self.serverStopped.set()
		except Exception, e:
			fl_log("FridaLink: Unable to start server!\n")
			self.server = None
			raise e

	def startServer(self):
		FrLModules.SanityChecks()
		FrLModules.GetNextModuleBase()

		if FrLSettings().getOverwriteSymbolName():
			fl_log("FridaLink: Symbol Overwrite enabled\n")
		else:
			fl_log("FridaLink: Symbol Overwrite disabled\n")

		if self.server is None:
			self.serverThread = threading.Thread(target=self.serverTask)
			self.serverThread.start()

	def stopServer(self):
		if self.serverRunning == True:
			self.server.shutdown()
	 		self.serverStopped.wait(3)
	 		self.serverThread = None

#def PLUGIN_ENTRY():
#    return FridaLinkPlugin()
if __name__ == '__main__':
	fridaLink = FridaLinkPlugin()
	fridaLink.init()
	fridaLink.run()
