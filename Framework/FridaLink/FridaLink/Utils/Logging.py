#
#  Logging.py
#  FridaLink Utils  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import msg
from idaapi import execute_sync
from idaapi import request_refresh, BWN_OUTPUT

from ..Settings.SettingsStorage import SettingsStorage as FrLSettings

class LogCallable:
	def __init__(self, message):
		self.message = message
	def __call__(self):
		msg(self.message)
		request_refresh(BWN_OUTPUT)

def fl_log(message):
	if FrLSettings().getLogEnabled() == True:
		log = LogCallable(message)
		execute_sync(log, 0)

__all__ = [
	'fl_log'
]
