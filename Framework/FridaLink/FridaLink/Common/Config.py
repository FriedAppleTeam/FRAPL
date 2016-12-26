#
#  Config.py
#  FridaLink Common
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

FL_CFG_DEVMODE = True
FL_CFG_DBGLOG = True

def DevModeEnabled():
	global FL_CFG_DEVMODE
	return FL_CFG_DEVMODE;

def DbgLogEnabled():
	global FL_CFG_DBGLOG
	return FL_CFG_DBGLOG;

__all__ = [
	'DevModeEnabled',
	'DbgLogEnabled'
]
