#
#  Modules.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import os

from idc import FirstSeg, SegName, MoveSegm, GetInputFile, SegStart, BADADDR
from idc import AskYN, Wait
from idaapi import getseg, set_segm_name, get_segm_by_name, load_loader_module

from ..Utils.Logging import fl_log as fl_log

g_NextLibBase = 0x0
g_AppBase = FirstSeg()

kModuleAlignment = 0x10000000

def SanityChecks():
	seg = FirstSeg()
	if SegName(seg) != GetInputFile().replace(' ', '_'):
		dlg = AskYN(0, "Name of the first segment for main module ('" + SegName(seg) + "') doesn't\nmatch main module's name ('" + GetInputFile() + "').\n\n" +
			"In order for the FridaLink to function correctly (i.e. resolve\nsymbols and load additional modules) this segment name\nshould be updated.\n\n" + 
			"Update first segment name to '" + GetInputFile() + "'?")
		if dlg == 1:
			set_segm_name(getseg(seg), GetInputFile())
			Wait()
			fl_log("FridaLink: set first sector name for main binary to '" + GetInputFile() + "'\n")

def GetNextModuleBase():
	global g_NextLibBase
	g_NextLibBase = FirstSeg()
	while SegStart(g_NextLibBase) != BADADDR:
		g_NextLibBase += kModuleAlignment
	fl_log("FridaLink: next module base = " + ("0x%012x" % g_NextLibBase) + "\n")

def LoadModule(platform, name, path):
	global g_NextLibBase

	if platform is not None:
		os_type = platform[:3]
		if os_type == "iOS":
			# check if it is custom or system framework
			app_idx = path.find(".app")
			
			if app_idx >=0:
				# custom framework
				local_path = path[app_idx+4:]
				bin_path = os.path.dirname(get_input_file_path())
				path = bin_path + local_path
			else:
				# system framework
				os_ver = platform[4:]
				home = os.path.expanduser("~")
				path = home + "/Library/Developer/Xcode/iOS DeviceSupport/" + os_ver + "/Symbols" + path
			
			# check if framework exists
			if os.path.exists(path) == False:
				fl_log("FridaLink: invalid path [ " + path + " ]\n")
				return

	fl_log("FridaLink: loading module '" + name + "' from [ " + path + " ]\n")
	res = load_loader_module(None, "macho", str(path), False)
	if res != 0:
		Wait()

		seg = get_segm_by_name("HEADER").startEA
		set_segm_name(getseg(seg), name)
		Wait()
		fl_log("FridaLink: set first sector name for loaded module to '" + name + "'\n")

		if seg < g_AppBase:
			fl_log("FridaLink: move module '" + name + "' to " + ('0x%012x' % g_NextLibBase) + "\n")

			# Move back all segments before main one (usually for OSX modules)
			while seg < g_AppBase:
				fl_log(('  0x%012x' % SegStart(seg)) + " -> " + ('0x%012x' % (SegStart(seg) + g_NextLibBase)) + ": " + SegName(seg) + "\n")
				MoveSegm(SegStart(seg), SegStart(seg) + g_NextLibBase, 0)
				Wait()
				seg = FirstSeg()

			g_NextLibBase += kModuleAlignment
			fl_log("FridaLink: next module base = " + ("0x%012x" % g_NextLibBase) + "\n")

__all__ = [
	'SanityChecks',
	'GetNextModuleBase',
	'LoadModule'
]
