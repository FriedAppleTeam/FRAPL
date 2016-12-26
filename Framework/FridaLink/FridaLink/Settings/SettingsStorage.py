#
#  SettingsStorage.py
#  FridaLink Settings  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import msg

from ..Common.Config import DbgLogEnabled
from ..Common.FridaLinkObject import FridaLinkObject

class SettingsStorage(FridaLinkObject):
	_shared_state = {}

	_host = "localhost"
	_port = 9999
	_cpuContextColumns = 1
	_overwriteSymbolName = False
	_logEnabled = DbgLogEnabled()

	def __init__(self):
		self.__dict__ = self._shared_state
		self.lockProperties()

	def getHost(self):
		return self._host

	def setHost(self, host):
		self._host = host

	def getPort(self):
		return self._port

	def setPort(self, port):
		self._port = port

	def getCpuContextColumns(self):
		return self._cpuContextColumns

	def setCpuContextColumns(self, columns):
		self._cpuContextColumns = columns

	def getOverwriteSymbolName(self):
		return self._overwriteSymbolName

	def setOverwriteSymbolName(self, overwrite):
		self._overwriteSymbolName = overwrite

	def getLogEnabled(self):
		return self._logEnabled

	def setLogEnabled(self, enabled):
		self._logEnabled = enabled

	def restore(self, storage):
		self._host = storage._host
		self._port = storage._port
		self._cpuContextColumns = storage._cpuContextColumns
		self._overwriteSymbolName = storage._overwriteSymbolName
		self._logEnabled = storage._logEnabled

__all__ = [
	'SettingsStorage'
]
