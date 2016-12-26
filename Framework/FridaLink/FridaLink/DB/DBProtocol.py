#
#  DBProtocol.py
#  FridaLink Settings  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

import sqlite3
import os

from idc import AskFile, AskYN

from ..Core.Types import DBEntry
from ..UI.CreateDbDialog import CreateDbDialog
from ..UI.ExecQueryDialog import ExecQueryDialog
from ..UI.CloseDbDialog import CloseDbDialog
from ..Common.FridaLinkObject import FridaLinkObject
from ..Utils.Logging import fl_log as fl_log

class DBProtocol(object):

	def __init__(self):
		super(DBProtocol, self).__init__()
		self.dbList = {}

	def createDB(self, db_id, db_path, db_table=None):
		if db_id in self.dbList:
			return
		
		if os.path.exists(db_path):
			dlg = AskYN(0, "Overwrite existing file?")
			if dlg != 1:
				return
			os.remove(db_path)

		self.dbList[db_id] = DBEntry(db_id, sqlite3.connect(db_path))

		connect = self.dbList[db_id].connect
		cursor = connect.cursor()
		cursor.execute("CREATE TABLE frl_desc (db_id)")
		
		cursor.execute("INSERT INTO frl_desc VALUES ('" + db_id + "')")
		connect.commit()

		fl_log("FridaLink: DB created [ %s | %s ]\n" % (db_id, db_path))

		if db_table is not None:
			cursor.execute(db_table)
			connect.commit()

	def showCreateDB(self):
		dbDlg = CreateDbDialog()
		dbDlg.Compile()
		dbDlg.db_path.value = "*.db"
		dbDlg.db_table.value = ""
		ok = dbDlg.Execute()
		if ok != 1:
			return

		db_id = dbDlg.db_id.value
		db_path = dbDlg.db_path.value
		db_table = dbDlg.db_table.value if dbDlg.db_table.value != "" else None

		self.createDB(db_id, db_path, db_table)

	def showOpenDB(self):
		filePath = AskFile(0, "*.db", "Open DB")
		if filePath is None:
			return

		connect = sqlite3.connect(filePath)
		cursor = connect.cursor()
		cursor.execute('SELECT db_id FROM frl_desc')
		db_id = cursor.fetchone()[0]

		if db_id is None:
			fl_log("FridaLink: DB ID in [%s] is None\n" % filePath)
			return

		if db_id in self.dbList:
			dlg = AskYN(0, "DB ID (%s) from [%s] aleady exists\nReload DB?" % (db_id, filePath))
			if dlg != 1:
				return

		self.dbList[db_id] = DBEntry(db_id, connect)
		fl_log("FridaLink: DB loaded [ %s | %s ]\n" % (db_id, filePath))

	def showExecQuery(self):
		db_list = []
		for db_entry in self.dbList:
			db_list.append(str(db_entry))

		if len(db_list) == 0:
			return;

		dbDlg = ExecQueryDialog(db_list)
		dbDlg.Compile()
		dbDlg.db_query.value = ""
		ok = dbDlg.Execute()
		if ok != 1:
			return

		db_id = db_list[dbDlg.db_id.value]
		db_query = dbDlg.db_query.value if dbDlg.db_query.value != "" else None

		if db_id in self.dbList:
			self.handleDbQuery(db_id, db_query)

	def showCloseDB(self):
		db_list = []
		for db_entry in self.dbList:
			db_list.append(str(db_entry))

		if len(db_list) == 0:
			return;

		dbDlg = CloseDbDialog(db_list)
		dbDlg.Compile()
		ok = dbDlg.Execute()
		if ok != 1:
			return

		db_id = db_list[dbDlg.db_id.value]
		if db_id in self.dbList:
			self.close(db_id)

	def closeAllDBs(self):
		for db_entry in self.dbList:
			self.close(db_entry)

	def handleDbQuery(self, db_id, query):
		if db_id not in self.dbList:
			return
			
		connect = self.dbList[db_id].connect
		cursor = connect.cursor()
		
		try:
			cursor.execute(query)
			#row = cursor.fetchone()
			#while row is not None:
			#	fl_log("FridaLink: DB : %s\n" % str(row))
			#	row = cursor.fetchone()
			for row in cursor.execute(query):
				fl_log("FridaLink: DB : %s\n" % str(row))
		except Exception, e:
			fl_log("FridaLink: Unable to execute query on \"%s\": %s\n" % (str(db_id), str(e)))
		
		connect.commit()

	def close(self, db_id):
		connect = self.dbList[db_id].connect
		connect.close()
		del self.dbList[db_id]
		fl_log("FridaLink: DB closed [ %s ]\n" % db_id)

__all__ = [
	'DBProtocol'
]
