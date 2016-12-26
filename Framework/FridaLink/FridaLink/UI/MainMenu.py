#
#  MainMenu.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import add_menu_item, del_menu_item

g_MenuList = list()

def RegisterMenuActions(handler):
	global g_MenuList
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Unload Plugin",           "SHIFT+CTRL+U", 0, handler.unloadPlugin, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Stop Server",             None,           0, handler.stopServer, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Start Server",            None,           0, handler.startServer, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Debug Log Toggle",        None,           0, handler.logToggle, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Symbol Overwrite Toggle", None,           0, handler.overwriteSymbolToggle, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Settings",           None,           0, handler.showSettings, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Close DB",                None,           0, handler.showCloseDB, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Execute DB Query",        None,           0, handler.showExecQuery, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Open DB",                 None,           0, handler.showOpenDB, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Create DB",               None,           0, handler.showCreateDB, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Step Over Breakpoint",    "SHIFT+CTRL+O", 0, handler.handleDebugStepOver, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Step Into Breakpoint",    "SHIFT+CTRL+I", 0, handler.handleDebugStepInto, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Release Breakpoint",      "SHIFT+CTRL+R", 0, handler.handleDebugContinue, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Target Log",         None,           0, handler.showTargetLog, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show FRAPL Log",          "SHIFT+CTRL+L", 0, handler.showFraplLog, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Address Converter",  "SHIFT+CTRL+A", 0, handler.showAddressConverter, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Module List",        None,           0, handler.showModuleList, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Memory Manager",     "SHIFT+CTRL+M", 0, handler.showMemoryManager, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Arbitrary Hooks",    None,           0, handler.showArbitraryHooks, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Replaced Funcs",     None,           0, handler.showReplacedFuncs, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show Import Hooks",       "SHIFT+CTRL+S", 0, handler.showImportHooks, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Show IDB Hooks",          None,           0, handler.showDatabaseHooks, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Execute Frida Script",    "SHIFT+CTRL+E", 0, handler.showExecScriptDlg, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Fetch Target Modules",    None,           0, handler.requestModules, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Load Module",             None,           0, handler.loadModule, ()))
	add_menu_item(					"Edit/Plugin/Frida Link/", "-",                       None,           0, handler.doNothing, ())
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Save Project",            None,           0, handler.saveProject, ()))
	g_MenuList.append(add_menu_item("Edit/Plugin/Frida Link/", "Load Project",            None,           0, handler.loadProject, ()))

def UnregisterMenuActions():
	global g_MenuList
	for menu in g_MenuList:
		del_menu_item(menu) 

__all__ = [
	'RegisterMenuActions',
	'UnregisterMenuActions'
]
