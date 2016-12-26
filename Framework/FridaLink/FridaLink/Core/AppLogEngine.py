#
#  AppLogEngine.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import SCOLOR_CREFTAIL, SCOLOR_DSTR

from ..UI.AppLogView import AppLogView

class AppLogEngineProtocol(object):

	def __init__(self):
		super(AppLogEngineProtocol, self).__init__()
		self.fraplLog = AppLogView()
		self.fraplLog.Create("FRAPL Log")
		self.targetLog = AppLogView()
		self.targetLog.Create("Target Log")

	def resetFraplLog(self):
		self.fraplLog.ClearLines()

	def resetTargetLog(self):
		self.targetLog.ClearLines()

	def showFraplLog(self):
		self.fraplLog.Show()
		self.fraplLog.Refresh()

	def showTargetLog(self):
		self.targetLog.Show()
		self.targetLog.Refresh()

	def handleFraplLog(self, log_type, log_entry):
		if log_type == "error":
			hdr_color = SCOLOR_CREFTAIL
		else:
			hdr_color = SCOLOR_DSTR
		self.fraplLog.addEntry("FRAPL", hdr_color, log_entry)

	def handleTargetLog(self, log_header, log_entry):
		self.targetLog.addEntry(log_header, SCOLOR_DSTR, log_entry)

__all__ = [
    'AppLogEngineProtocol'
]
