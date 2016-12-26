#
#  Types.py
#  FridaLink Core
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

# **** HOOKS

class HookBase(object):
	def __init__(self):
		super(HookBase, self).__init__()
		self.id 			= 0 		# usually address of the element
		self.type 			= "unknown"	# type of the element (instruction/function)
		self.address		= 0			# address of the element in IDB
		self.module			= "unknown"	# name of the element's module
		self.once			= False		# detach hook after first trigger

class InstHook(HookBase):
	def __init__(self):
		super(InstHook, self).__init__()
		self.type 			= "inst"
		self.mnemonic		= "unknown"	# mnemonic of the element's symbol
		self.script			= ""		# custom script for Frida server
		self.recentSrcFile	= None		# recent script source file
		self.breakpoint		= False		# set breakpoint

class FuncHook(HookBase):
	def __init__(self):
		super(FuncHook, self).__init__()
		self.type 				= "func"
		self.symbol				= "unknown"	# name of the element's symbol
		self.moduleImport		= False		# import symbol
		self.enterScript		= ""		# custom onEnter script for Frida server
		self.enterRecentSrcFile	= None		# onEnter recent source file
		self.leaveScript		= ""		# custom onLeave script for Frida server
		self.leaveRecentSrcFile	= None		# onLeave recent source file

class HookEntry(object):

	UDP_NONE		= 0
	UPD_TRIGGER		= (1 << 0)			# update triggering type
	UPD_SCRIPT		= (1 << 1)			# update custom script
	UPD_MEMLIST		= (1 << 2)			# update linked memory list

	def __init__(self, hook):
		super(HookEntry, self).__init__()
		self.hook 			= hook		# hook instance
		self.platform		= ""		# target platform
		self.arch			= ""		# target architercture
		self.cpu_ctx		= {}		# CPU context
		self.stack			= None		# stack object
		self.backtrace		= None		# backtrace object
		self.mem_list		= []		# array of memory ranges to be updated

	def genSetRequest(self):
		hook_dict = self.hook.__dict__.copy()
		hook_dict['id'] 		= "0x%X" % self.hook.id
		hook_dict['address'] 	= "0x%X" % self.hook.address
		hook_dict['mem_list'] 	= self.mem_list
		return hook_dict

	def genDelRequest(self):
		return {
			"id": 		"0x%X" % self.hook.id,
			"type": 	self.hook.type,
			"address": 	"0x%X" % self.hook.address, 
			"module": 	self.hook.module,
			"all":		False
		};

	def genUpdRequest(self, flags):
		hook_dict = {
			"id": 		"0x%X" % self.hook.id,
			"type":		self.hook.type,
			"address": 	"0x%X" % self.hook.address,
		};

		if self.hook.type == "inst":
			hook_dict['mnemonic'] = self.hook.mnemonic
		elif self.hook.type == "func":
			hook_dict['symbol'] = self.hook.symbol

		if flags & self.UPD_TRIGGER:
			hook_dict['once'] = self.hook.once

		if flags & self.UPD_SCRIPT:
			if self.hook.type == "inst":
				hook_dict['script'] = self.hook.script
			elif self.hook.type == "func":
				hook_dict['enterScript'] = self.hook.enterScript
				hook_dict['leaveScript'] = self.hook.leaveScript

		if flags & self.UPD_MEMLIST:
			hook_dict['mem_list'] = self.mem_list

		return hook_dict

	def setResponse(self, platform, arch, response):
		self.platform = platform
		self.arch = arch
		self.backtrace = Backtrace(platform, arch, response['backtrace'])
		self.cpu_ctx = response['cpu_ctx']
		self.stack =  Stack(platform, arch, response['stack'])

# **** FUNCTION REPLACE

class FuncReplace(object):

	UDP_NONE		= 0
	UPD_SCRIPT		= (1 << 0)			# update custom script

	def __init__(self):
		super(FuncReplace, self).__init__()
		self.id 			= 0 		# usually address of the element
		self.address		= 0			# address of the element in IDB
		self.module			= "unknown"	# name of the element's module
		self.symbol			= "unknown"	# name of the element's symbol
		self.moduleImport	= False		# import symbol
		self.ret_type		= ""		# function return type
		self.arg_types		= ""		# list of argument types
		self.arg_names		= ""		# list of argument names
		self.script			= ""		# custom script for Frida server
		self.args_str		= ""		# string representation of arguments
		self.recentSrcFile	= None		# recent script source file

	def genSetRequest(self):
		replace_dict = self.__dict__.copy()
		replace_dict['id'] 		= "0x%X" % self.id
		replace_dict['address'] = "0x%X" % self.address
		del replace_dict['args_str']
		del replace_dict['recentSrcFile']
		return replace_dict

	def genDelRequest(self):
		return {
			"id": 		"0x%X" % self.id,
			"address": 	"0x%X" % self.address, 
			"module": 	self.module,
			"all":		False
		};

	def genUpdRequest(self, flags):
		replace_dict = {
			"id": 			"0x%X" % self.id,
			"address": 		"0x%X" % self.address,
			"symbol":		self.symbol,
			"ret_type": 	self.ret_type,
			"arg_types":	self.arg_types,
			"arg_names":	self.arg_names
		};

		if flags & self.UPD_SCRIPT:
			replace_dict['script'] = self.script

		return replace_dict

# **** STACK

class StackEntry(object):
	def __init__(self, address, data, symbol, sp):
		super(StackEntry, self).__init__()
		self.address = address
		self.data = data;
		self.symbol = symbol;
		self.sp = sp;

class Stack(object):
	def __init__(self, platform, arch, content):
		super(Stack, self).__init__()
		self.platform = platform
		self.arch = arch
		self.sp = int(content['sp'], 16)
		self.before = content['before']
		self.after = content['after']
		self.entries = []

		if arch == "x64" or arch == "arm64":
			wordSize = 8
		else:
			wordSize = 4

		addr = self.sp - (self.before * wordSize)
		for i in xrange(0, self.before + 1 + self.after):
			data = int(content['dump'][i], 16)
			symbol = content['symbols'][i]
			self.entries.append(StackEntry(addr, data, symbol, True if addr == self.sp else False))
			addr += wordSize

	def getCount(self):
		return len(self.entries)

	def getEntry(self, index):
		return (
			self.entries[index].address, 
			self.entries[index].data, 
			self.entries[index].symbol, 
			self.entries[index].sp
		)

# **** BACKTRACE

class BacktraceEntry(object):
	def __init__(self, data):
		super(BacktraceEntry, self).__init__()
		self.mod_name = data['mod_name']
		self.mod_path = data['mod_path']
		self.mod_base = int(data['mod_base'], 16)
		self.sym_addr = int(data['sym_addr'], 16)
		self.sym_name = data['sym_name']
		self.sym_call = int(data['sym_call'], 16)
		self.idb_addr = False

	def serialize(self):
		return self.__dict__
		
class Backtrace(object):
	def __init__(self, platform, arch, data):
		super(Backtrace, self).__init__()
		self.platform = platform
		self.arch = arch
		self.entries = []
		for entry in data:
			self.entries.append(BacktraceEntry(entry))

	def getEntry(self, index):
		return self.entries[index]

	def getCount(self):
		return len(self.entries)

	def getArray(self):
		arr = []
		for entry in self.entries:
			entry_dict = entry.serialize()
			entry_dict['mod_base'] = "0x%X" % entry_dict['mod_base']
			entry_dict['sym_addr'] = "0x%X" % entry_dict['sym_addr']
			entry_dict['sym_call'] = "0x%X" % entry_dict['sym_call']
			arr.append(entry_dict)
		return arr

# **** MEMORY

class MemoryRegion(object):
	def __init__(self, mem_id, address, size, comment):
		super(MemoryRegion, self).__init__()
		self.mem_id = mem_id
		self.address = address
		self.size = size
		self.comment = comment
		self.content = []

	def serialize(self):
		return {
			'mem_id'	: self.mem_id,
			'address'	: "0x%X" % self.address,
			'size'		: self.size
		}

# **** IMPORT

class ImportEntry(object):
	def __init__(self, module, address, symbol):
		super(ImportEntry, self).__init__()
		self.module = module
		self.address = address
		self.symbol = symbol

# **** DB

class DBEntry(object):
	def __init__(self, db_id, connect):
		super(DBEntry, self).__init__()
		self.db_id = db_id
		self.connect = connect
