//
// FrAFridaLink.js
// Fried Apple Framework
//
// Created by Alexander Hude on 24/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

var kFridaLink_ExecuteScript  		= "frl_exec_script";	// Execute custom script (IDA -> FRAPL)
var kFridaLink_TargetInfo			= "frl_target_info";	// Request information about target (IDA <- FRAPL)
var kFridaLink_ModulesRequest  		= "frl_modules_req";	// Request list of all modules (IDA -> FRAPL)
var kFridaLink_ModulesResponse 		= "frl_modules_resp";	// Response with the list of all modules (IDA <- FRAPL)
var kFridaLink_SetHookRequest		= "frl_sethook_req";	// Hook instruction or function (IDA -> FRAPL)
var kFridaLink_DelHookRequest		= "frl_delhook_req";	// Unhook instruction or function (IDA -> FRAPL)
var kFridaLink_UpdHookRequest		= "frl_updhook_req";	// Update hook for instruction or function (IDA -> FRAPL)
var kFridaLink_SetReplaceRequest  	= "frl_setrepl_req";	// Replace function (IDA -> FRAPL)
var kFridaLink_DelReplaceRequest	= "frl_delrepl_req";	// Restore function (IDA -> FRAPL)
var kFridaLink_UpdReplaceRequest	= "frl_updrepl_req";	// Update replaced function (IDA -> FRAPL)
var kFridaLink_AddMemRequest		= "frl_addmem_req";		// Start monitoring memory range (IDA -> FRAPL)
var kFridaLink_DelMemRequest		= "frl_delmem_req";		// Stop monitoring memory range (IDA -> FRAPL)
var kFridaLink_FetchMemRequest		= "frl_fetchmem_req";	// Request memory region content (IDA -> FRAPL)
var kFridaLink_FetchMemResponse		= "frl_fetchmem_resp";	// Response with memory region content (IDA <- FRAPL)
var kFridaLink_Ack    	  			= "frl_ack";			// acknowledgment packet (IDA -> FRAPL)
var kFridaLink_ProcessBacktrace		= "frl_bktrc_proc";		// Request backtrace processing from IDA (IDA <- FRAPL)
var kFridaLink_HookResponse 		= "frl_hook_resp";		// Response on instruction or function hook (IDA <- FRAPL)
var kFridaLink_ReplaceResponse 		= "frl_replace_resp";	// Response on function replace (IDA <- FRAPL)
var kFridaLink_FraplLogEntry		= "frl_frapl_log";		// Add FRAPL log entry
var kFridaLink_TargetLogEntry		= "frl_target_log";		// Add target log entry
var kFridaLink_DBQuery				= "frl_db_query";		// Execute DB query
var kFridaLink_DebugContinue		= "frl_debug_cont";		// Breakpoint continue execution

var FrlInstHooks = {}
var FrlFuncHooks = {}
var FrlFuncReplace = {}
var FrlMemoryMap = {}

var FrlGlobal = {}

function FrLGetTargetInfo()
{
	schedule_sync(fraMainQueue, function () {
		send({ 
			id: 	kMessageID_Link, 
			data: 	{ 
				req_id: 	kFridaLink_TargetInfo, 
				platform:	GetTargetOS(), 
				arch:		Process.arch, 
			}
		});
	});
}

function FrLGetBacktraceDetails(methodName, pc, backtrace)
{
	var addr_list = [pc];
	addr_list = addr_list.concat(backtrace);
	var output = [];

	// push hook entry
	output.push({
			mod_name: "HOOK",
			mod_path: "",
			mod_base: "0x0",
			sym_addr: "0x0",
			sym_name: methodName,
			sym_call: "0x0"
		})

	// push backtrace entries
	for(var i in addr_list)
	{
		var entry = {
			mod_name: "",
			mod_path: "",
			mod_base: "0x0",
			sym_addr: "0x0",
			sym_name: "UNKNOWN",
			sym_call: addr_list[i]
		};
		var module = Process.findModuleByAddress(addr_list[i]);
		var symDetails = fra_dladdr(addr_list[i]);

		if(module != null)
		{
			entry['mod_name'] = module.name;
			entry['mod_path'] = "";
			entry['mod_base'] = module.base;

			if (symDetails.dli_saddr == 0)
			{
				entry['mod_path'] = module.path;
				entry['sym_addr'] = "0x0";
				entry['sym_name'] = "";
			}
			else
			{
				entry['mod_path'] = module.path;
				entry['sym_addr'] = symDetails.dli_saddr;
				entry['sym_name'] = symDetails.dli_sname;
			}
		}

		output.push(entry);
	}

	return output;
}

function FrLGetStackDetails(sp, before, after)
{
	var wordSize = GetWordSize();

	var addr = ptr(sp).sub(wordSize*before);
	var end = addr.add((before + 1 + after) * wordSize);
	
	var output = {
		sp: 		ptr(sp),
		before:		before,
		after:		after,
		dump:		[],
		symbols:	[]
	};

	while (! addr.equals(end))
	{
		try {
			var data = Memory.readPointer(addr);
			var symDetails = fra_dladdr(data);

			output.dump.push(data);
			if (symDetails.dli_fbase == "0x0")
				output.symbols.push(["0x0", "", "", "0x0"]);
			else
				output.symbols.push([
					symDetails.dli_fbase,
					symDetails.dli_fname.substring(symDetails.dli_fname.lastIndexOf("/") + 1),
					symDetails.dli_sname,
					symDetails.dli_saddr
					]);
		} catch (e) {
			FraplError("Unable to acceess stack [ " + addr + " : " + wordSize.toString() + " ]");
			output.dump.push(ptr("0xDEADBEEF"));
		}
		addr = addr.add(wordSize);
	}

	return output;	
}

function FrLProcessBacktrace(methodName, pc, backtrace)
{
	schedule_sync(fraMainQueue, function () {
		var request = FrLGetBacktraceDetails(methodName, pc, backtrace);

		send({ 
			id: 	kMessageID_Link, 
			data: 	{ 
				req_id: 	kFridaLink_ProcessBacktrace, 
				platform:	GetTargetOS(), 
				arch:		Process.arch, 
				request:	request 
			}
		});
	});
}

function FrLRequestModules()
{
	schedule_sync(fraMainQueue, function () {
		send({ 
			id: 	kMessageID_Link, 
			data: 	{ 
				req_id:		kFridaLink_ModulesResponse, 
				response:	Process.enumerateModulesSync()
			} 
		});

		FraplLog("Module list request complete");
	});
}

function FrLInstallHook(hookInfo)
{
	if (hookInfo.type == "inst")
	{
		var module = Process.findModuleByName(hookInfo.module);
		if (module == null)
			return;

		var realAddress = module.base.add(ptr(hookInfo.address));

		try {
	 		var handler = Interceptor.attach(realAddress, function (args) {

	 			const hook = hookInfo
			  	const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
			   	const context = this.context;

				const mnemonic = FrlInstHooks[hook.id].mnemonic;
				const mem_list = FrlInstHooks[hook.id].mem_list;
				const script = FrlInstHooks[hook.id].script;
				const once = FrlInstHooks[hook.id].once;
				const breakpoint = FrlInstHooks[hook.id].breakpoint;

				FrlInstHooks[hook.id].count += 1;
				const count = FrlInstHooks[hook.id].count;

				// execute custom script
				try {
					if (script != "")
						eval(script);
				} catch (e) {
			 		var log = realAddress + ": " + hook.mnemonic;
			 		FraplError("Unable to execute script in [ " + log + " ]: " + e);
				}

				schedule_sync(fraMainQueue, function () {
					var response = { 
						id: 		hook.id, 
						type: 		hook.type, 
						address: 	hook.address, 	// for FRAPL client's log
						realAddr: 	realAddress, 	// for FRAPL client's log
						mnemonic: 	hook.mnemonic, 	// for FRAPL client's log
						cpu_ctx: 	context, 
						backtrace: 	FrLGetBacktraceDetails(mnemonic, context.pc, backtrace),
						stack:		FrLGetStackDetails(context.sp, 20, 20),
						memory: 	FrLDumpMemory(mem_list),
						count:		count
					};

					send({ 
						id: 	kMessageID_Link, 
						data: 	{ 
							req_id:		kFridaLink_HookResponse, 
							platform:	GetTargetOS(), 
							arch: 		Process.arch, 
							response:	response 
						} 
					});
				});

				if (breakpoint == true)
				{
			 		var log = realAddress + ": " + hookInfo.mnemonic;
			 		FraplLog("Break at [ " + log + " ]. Wait for continue ...");
					FrLBreakPoint();
				}

				if (once == true)
				{
			 		var handler = FrlInstHooks[hookInfo.id].handler;
			 		handler.detach();
					delete FrlInstHooks[hookInfo.id];

			 		var log = realAddress + ": " + hookInfo.mnemonic;
			 		FraplLog("Autoremove instruction hook [ " + log + " ]");
				}
			});

			FrlInstHooks[hookInfo.id] = {
				handler  	: handler,
				once	 	: hookInfo.once,
				mnemonic 	: hookInfo.mnemonic,
				mem_list 	: hookInfo.mem_list,
				script   	: hookInfo.script,
				breakpoint	: hookInfo.breakpoint,
				count	 	: 0
			};

			var log = realAddress + ": " + hookInfo.mnemonic;
			FraplLog("Install instruction hook [ " + log + " ]");

		} catch (e) {
			console.log(e);
			var log = realAddress + ": " + hookInfo.mnemonic;
	 		FraplError("Unable to set instruction hook [ " + log + " ]");

			var response = { 
				id: 		hookInfo.id, 
				type: 		hookInfo.type, 
				count:		0
			};

			send({ 
				id: 	kMessageID_Link, 
				data: 	{ 
					req_id:		kFridaLink_HookResponse, 
					platform:	GetTargetOS(), 
					arch: 		Process.arch, 
					response:	response 
				} 
			});
		}
	}
	else if (hookInfo.type == "func")
	{
		var realAddress;
		if (hookInfo.moduleImport == false)
		{
			var module = Process.findModuleByName(hookInfo.module);
			if (module == null)
				return
			realAddress = module.base.add(ptr(hookInfo.address));
		}
		else
		{
			var symbolName = hookInfo.symbol
			if (symbolName[0] == '_')
				symbolName = symbolName.substring(1);
			realAddress = Module.findExportByName(hookInfo.module, symbolName)
		}

		try {
	 		var handler = Interceptor.attach(realAddress, {
			    onEnter: function (args) {
		 			const hook = hookInfo
				  	const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
				   	const context = this.context;

					const symbol = FrlFuncHooks[hook.id].symbol;
					const mem_list = FrlFuncHooks[hook.id].mem_list;
					const enterScript = FrlFuncHooks[hook.id].enterScript;

			    	FrlFuncHooks[hook.id].count += 1;
					const count = FrlFuncHooks[hook.id].count;

					// execute custom onEnter script
					try {
						if (enterScript != "")
							eval(enterScript);
					} catch (e) {
				 		var log = realAddress + ": " + hook.symbol;
				 		FraplError("Unable to execute enter script in [ " + log + " ]: " + e);
					}

					schedule_sync(fraMainQueue, function () {

						var response = { 
							id: 		hook.id, 
							type: 		hook.type, 
							address: 	hook.address, 	// for FRAPL client's log
							realAddr: 	realAddress, 	// for FRAPL client's log
							symbol: 	hook.symbol, 	// for FRAPL client's log
							cpu_ctx: 	context, 
							backtrace: 	FrLGetBacktraceDetails(symbol, context.pc, backtrace),
							stack:		FrLGetStackDetails(context.sp, 20, 20),
							memory: 	FrLDumpMemory(mem_list),
							count:		count
						};

						send({ 
							id: 	kMessageID_Link, 
							data: 	{ 
								req_id:		kFridaLink_HookResponse, 
								platform:	GetTargetOS(), 
								arch: 		Process.arch, 
								response:	response 
							}
						});
					});
	    		},
	    		onLeave: function (retval) {
	    			const hook = hookInfo
					const once = FrlFuncHooks[hook.id].once;
	    			const leaveScript = FrlFuncHooks[hook.id].leaveScript;
					// execute custom onLeave script
					try {
						if (leaveScript != "")
							eval(leaveScript);
					} catch (e) {
				 		var log = realAddress + ": " + hook.symbol;
				 		FraplError("Unable to execute leave script in [ " + log + " ]: " + e);
					}

					if (once == true)
					{
				 		var handler = FrlFuncHooks[hookInfo.id].handler;
				 		handler.detach();
						delete FrlFuncHooks[hookInfo.id];

				 		var log = realAddress + ": " + hookInfo.symbol;
				 		FraplLog("Autoremove function hook [ " + log + " ]");
					}
	    		}
			});

			FrlFuncHooks[hookInfo.id] = {
				handler     : handler,
				once	 	: hookInfo.once,
				symbol 	    : hookInfo.symbol,
				mem_list    : hookInfo.mem_list,
				enterScript : hookInfo.enterScript,
				leaveScript : hookInfo.leaveScript,
				count	 	: 0
			};

			var log = realAddress + ": " + hookInfo.symbol;
			FraplLog("Install function hook [ " + log + " ]");

		} catch (e) {
			var log = realAddress + ": " + hookInfo.symbol;
	 		FraplError("Unable to set function hook [ " + log + " ]");

			var response = { 
				id: 		hookInfo.id, 
				type: 		hookInfo.type, 
				count:		0
			};

			send({ 
				id: 	kMessageID_Link, 
				data: 	{ 
					req_id:		kFridaLink_HookResponse, 
					platform:	GetTargetOS(), 
					arch: 		Process.arch, 
					response:	response 
				} 
			});
		}
	}
	else
	{
		// unknown type
	}
}

function FrLRemoveHook(hookInfo)
{
	if (hookInfo.all == true)
	{
		// unhook instructions
		FraplLog("Remove all FridaLink instruction hooks");
		for(var hook_id in FrlInstHooks)
		{
	 		var desc = FrlInstHooks[hook_id];
	 		desc.handler.detach();

			delete FrlInstHooks[hook_id];			
		}

		// unhook functions
		FraplLog("Remove all FridaLink function hooks");
		for(var hook_id in FrlFuncHooks)
		{
	 		var desc = FrlFuncHooks[hook_id];
	 		desc.handler.detach();

			delete FrlFuncHooks[hook_id];			
		}

		return
	}

	if (hookInfo.type == "inst")
	{
		if (! (hookInfo.id in FrlInstHooks))
			return

		var module = Process.findModuleByName(hookInfo.module);
		if (module == null)
			return

 		var desc = FrlInstHooks[hookInfo.id];
 		desc.handler.detach();

		var realAddress = module.base.add(ptr(hookInfo.address));
 		var log = realAddress + ": " + desc.mnemonic;
		FraplLog("Remove Instruction Hook [ " + log + " ]");

		delete FrlInstHooks[hookInfo.id];
	}
	else if (hookInfo.type == "func")
	{
		if (! (hookInfo.id in FrlFuncHooks))
			return

		var module = Process.findModuleByName(hookInfo.module);
		if (module == null)
			return

 		var desc = FrlFuncHooks[hookInfo.id];
 		desc.handler.detach();

		var realAddress = module.base.add(ptr(hookInfo.address));
 		var log = realAddress + ": " + desc.symbol;
		FraplLog("Remove Function Hook [ " + log + " ]");

		delete FrlFuncHooks[hookInfo.id];
	}
	else
	{
		// unknown type
	}
}

function FrLUpdateHook(hookInfo)
{
	if (hookInfo.type == "inst")
	{
		if (! (hookInfo.id in FrlInstHooks))
			return

		FrlInstHooks[hookInfo.id].mnemonic = hookInfo.mnemonic

		var log = hookInfo.address + ": " + hookInfo.mnemonic;

		if ("once" in hookInfo)
		{
			FrlInstHooks[hookInfo.id].once = hookInfo.once
			FraplLog("Update triggering type for [ " + log + " ]");
		}

		if ("script" in hookInfo)
		{
			FrlInstHooks[hookInfo.id].script = hookInfo.script
			FraplLog("Update script for [ " + log + " ]");
		}

		if ("mem_list" in hookInfo)
		{
			FraplLog("Update linked memory for [ " + log + " ]");
			FrlInstHooks[hookInfo.id].mem_list = hookInfo.mem_list
		}
	}
	else if (hookInfo.type == "func")
	{
		if (! (hookInfo.id in FrlFuncHooks))
			return

		FrlFuncHooks[hookInfo.id].symbol = hookInfo.symbol
		var log = hookInfo.address + ": " + hookInfo.symbol;

		if ("once" in hookInfo)
		{
			FrlFuncHooks[hookInfo.id].once = hookInfo.once
			FraplLog("Update triggering type for [ " + log + " ]");
		}

		if ("mem_list" in hookInfo)
		{
			FraplLog("Update linked memory for [ " + log + " ]");
			FrlFuncHooks[hookInfo.id].mem_list = hookInfo.mem_list
		}

		if ("enterScript" in hookInfo)
		{
			FraplLog("Update enterScript for [ " + log + " ]");
			FrlFuncHooks[hookInfo.id].enterScript = hookInfo.enterScript
		}

		if ("leaveScript" in hookInfo)
		{
			FraplLog("Update leaveScript for [ " + log + " ]");
			FrlFuncHooks[hookInfo.id].leaveScript = hookInfo.leaveScript
		}
	}
}

function FrLReplaceImpl(replaceInfo)
{
	var realAddress;
	if (replaceInfo.moduleImport == false)
	{
		var module = Process.findModuleByName(replaceInfo.module);
		if (module == null)
			return
		realAddress = module.base.add(ptr(replaceInfo.address));
	}
	else
	{
		var symbolName = replaceInfo.symbol
		if (symbolName[0] == '_')
			symbolName = symbolName.substring(1);
		realAddress = Module.findExportByName(replaceInfo.module, symbolName)
	}

	try {
		var callback;
		var callback_script = 
			"var frlOriginalImpl = " + "new NativeFunction(realAddress, " + 
				replaceInfo.ret_type + "," +
				"[" + replaceInfo.arg_types + "]" +
			");\n" + 
			"callback = new NativeCallback(function (" + replaceInfo.arg_names + ") {" +
			replaceInfo.script +
			"}," + replaceInfo.ret_type + ", [" + replaceInfo.arg_types + "]);"

		eval(callback_script);

		Interceptor.replace(realAddress, callback); 

		FrlFuncReplace[replaceInfo.id] = {
			symbol	 : replaceInfo.symbol,
			realAddr : realAddress
		};

		var log = realAddress + ": " + replaceInfo.symbol;
		FraplLog("Replace function implementation [ " + log + " ]");

	} catch (e) {
 		var log = realAddress + ": " + replaceInfo.symbol;
 		FraplError("Unable to replace [ " + log + " ]");

		var response = { 
			id: 		replaceInfo.id, 
			count:		0
		};

		send({ 
			id: 	kMessageID_Link, 
			data: 	{ 
				req_id:		kFridaLink_ReplaceResponse, 
				response:	response 
			} 
		});

	}
}

function FrLRevertImpl(replaceInfo)
{
	if (replaceInfo.all == true)
	{
		for(var repl_id in FrlFuncReplace)
		{
			var desc = FrlFuncHooks[repl_id];
			Interceptor.revert(desc.realAddr);
			delete FrlFuncHooks[repl_id];
		}
		
		return
	}

	if (! (replaceInfo.id in FrlFuncReplace))
		return;

	var realAddress = FrlFuncReplace[replaceInfo.id].realAddr;

	var log = realAddress + ": " + FrlFuncReplace[replaceInfo.id].symbol;
	try {
		Interceptor.revert(realAddress);
		var log = realAddress + ": " + FrlFuncReplace[replaceInfo.id].symbol;
		FraplLog("Revert function implementation [ " + log + " ]");

		delete FrlFuncReplace[replaceInfo.id];
	} catch (e) {
		console.log(e);
 		FraplError("Unable to revert [ " + log + " ]");
	}
}

function FrLUpdateReplaceImpl(replaceInfo)
{
	if (! (replaceInfo.id in FrlFuncReplace))
		return;

	var realAddress = FrlFuncReplace[replaceInfo.id].realAddr;

	var log = realAddress + ": " + FrlFuncReplace[replaceInfo.id].symbol;
	try {
		Interceptor.revert(realAddress);

		var callback;
		var callback_script = 
			"var frlOriginalImpl = " + "new NativeFunction(realAddress, " + 
				replaceInfo.ret_type + "," +
				"[" + replaceInfo.arg_types + "]" +
			");\n" + 
			"callback = new NativeCallback(function (" + replaceInfo.arg_names + ") {" +
			replaceInfo.script +
			"}," + replaceInfo.ret_type + ", [" + replaceInfo.arg_types + "]);"

		eval(callback_script);

		Interceptor.replace(realAddress, callback); 

		FrlFuncReplace[replaceInfo.id].symbol = replaceInfo.symbol;

		var log = realAddress + ": " + replaceInfo.symbol;
		FraplLog("Update replaced function implementation [ " + log + " ]");

	} catch (e) {
		console.log(e);
 		FraplError("Unable to update [ " + log + " ]");
	}
}

function FrLAddMemory(memInfo)
{
	FrlMemoryMap[memInfo.mem_id] = {
		address: memInfo.address,
		size: memInfo.size
	}
	var log = memInfo.address + ": " + memInfo.size.toString();
	FraplLog("Add memory range to monitor [ " + log + " ]");
}

function FrLDelMemory(memInfo)
{
	if (memInfo.all == true)
	{
		for (var memRange in FrlMemoryMap)
		{
			delete FrlMemoryMap[memRange];
		}
		FraplLog("Delete all memory ranges from monitor");
	}
	else
	{
		if (memInfo.mem_id in FrlMemoryMap)
		{
			var log = FrlMemoryMap[memInfo.mem_id].address + ": " + FrlMemoryMap[memInfo.mem_id].size.toString();
			FraplLog("Delete memory range from monitor [ " + log + " ]");
			delete FrlMemoryMap[memInfo.mem_id];
		}
	}
}

function FrLDumpMemory(mem_list)
{
	var output = []

	for(var i in mem_list)
	{
		if (mem_list[i] in FrlMemoryMap)
		{
			var addr = ptr(FrlMemoryMap[mem_list[i]].address);
			var size = FrlMemoryMap[mem_list[i]].size;
			try {
				var arrayBuffer = Memory.readByteArray(addr, size);
				var entry = {
					mem_id:  mem_list[i],
					content: Array.from(arrayBuffer),
				};
				output.push(entry);
			} catch (e) {
				FraplError("Unable to acceess [ " + addr + " : " + size.toString() + " ]");
			}
		}
	}

	return output;
}

function FrLFetchMemory(memInfo)
{
	schedule_sync(fraMainQueue, function () {
		var addr = ptr(memInfo.address);
		var size = memInfo.size;
		try {
			FraplLog("Fetching memory range [ " + addr + " : " + size.toString() + " ]");
			
			var arrayBuffer = Memory.readByteArray(addr, size);
			var entry = {
				mem_id:  memInfo.mem_id,
				content: Array.from(arrayBuffer),
			};

			send({ 
				id: 	kMessageID_Link, 
				data: 	{ 
					req_id:		kFridaLink_FetchMemResponse, 
					platform:	GetTargetOS(), 
					arch: 		Process.arch, 
					response:	entry 
				}
			});
		} catch (e) {
			FraplError("Unable to acceess [ " + addr + " : " + size.toString() + " ]");
		}
	});
}

function FrLBreakPoint()
{
	recv(kFridaLink_DebugContinue, function callback(msg) {} ).wait();
}

function FrLExecScript(script)
{
	schedule_sync(fraMainQueue, function () {
		FraplLog("Execute custom script...");
		try {
			eval(script);
		} catch (e) {
			FraplError("Unable to execute custom script: " + e);
		}
		FraplLog("... custom script complete");
	});
}

function FrLExecQuery(db_id, query)
{
	send({ 
		id: 	kMessageID_Link, 
		data: 	{ 
			req_id:	kFridaLink_DBQuery, 
			db_id:  db_id,
			query:	query 
		}
	});
}

function FrLCleanup()
{
	for(var hook_id in FrlInstHooks)
	{
		var desc = FrlInstHooks[hook_id];
 		desc.handler.detach();
		delete FrlInstHooks[hook_id];
	}

	for(var hook_id in FrlFuncHooks)
	{
		var desc = FrlFuncHooks[hook_id];
 		desc.handler.detach();
		delete FrlFuncHooks[hook_id];
	}

	for(var repl_id in FrlFuncReplace)
	{
		var desc = FrlFuncHooks[repl_id];
		Interceptor.revert(desc.realAddr);
		delete FrlFuncHooks[repl_id];
	}
}
