//
// FrAClientCore.js
// Fried Apple Framework
//
// Created by Alexander Hude on 09/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

const os = require('os')
const co = require('co');
const fs = require('fs');
const net = require('net');
const uuid = require('uuid');
const frida = require('frida');
const load = require('frida-load');
const utils = require('./FrAUtils.js');
const colors = require('colors');

include('./FRAPL/FrAFridaLink.js');  

var startMode = -1;
var startTarget = "";
var startBundleId = "";
var startRemote = false;
var remoteDevice = null;
var serverScriptName = "";
var autoLink = false;
var autoResume = false;

var currentPID = -1;
var currentSession = null;
var currentScript = null;
var currentAPI = null;
var clientMessageListener = null;
var dbgIncludeList = [];
var dbgSourceLines = [];

var hasFridaLinkRPC = false;
var hasHelperLibRPC = false;

const LINK_HOST = "127.0.0.1";
const LINK_PORT = 9999;
var linkSocket = null;

var pingCount = 0;

var linkQueue = []

// *** Frida Setup

colors.setTheme({
  frapl: 		['white'],
  info:			['white'],
  error: 		['white'],
  file:			["white"],
  include:		["white"],
  bt_graphic: 	['white'],
  bt_sym_idx: 	['white'],
  bt_mod_name:	['white'],
  bt_sym_addr:	['white'],
  bt_sym_name: 	['white']
});

function QueueSend(data)
{
	linkQueue.push(data)
	if (linkQueue.length == 1)
	{		
		var dataLength = Buffer.byteLength(linkQueue[0], 'utf8');
		var header = ("0000000" + dataLength).slice(-8);
		linkSocket.write(header + linkQueue[0]);
	}
}

function QueueSendNext()
{
	linkQueue.shift();
	if (linkQueue.length != 0){
		var dataLength = Buffer.byteLength(linkQueue[0], 'utf8');
		var header = ("0000000" + dataLength).slice(-8);
		linkSocket.write(header + linkQueue[0]);
	}
}

function HandleLinkResponse(inJSON)
{
	switch (inJSON.req_id)
	{
		case kFridaLink_Ack:
			QueueSendNext();
			break;
		case kFridaLink_ModulesRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLRequestModules();
			break;
		case kFridaLink_ProcessBacktrace:
			var backtrace = inJSON.request;
			// first entry in backtrace is actually hooked method (onEnter)
			console.log("FRAPL".frapl + ":", "--[".bt_graphic, "HOOK on", backtrace[0].sym_name.bt_sym_name, "]".bt_graphic)
			// dump backtrace starting from second entry (indexed with zero)
			for (var i = 1; i < backtrace.length; i++)
			{
				var index = utils.printWithLeftPadding(i-1, 2);
				var module = utils.printWithRightPadding(backtrace[i].mod_name, 30);
				var base = ""
				var offset = ""
				if (backtrace[i].sym_addr != "0x0")
				{
					base = "0x" + utils.printWithLeftPadding(backtrace[i].sym_addr.substring(2), 12, "0");
					offset = "0x" + utils.printWithLeftPadding((parseInt(backtrace[i].sym_call,16) - parseInt(backtrace[i].sym_addr, 16)).toString(16), 6, "0");
				}
				else
				{
					base = "0x" + utils.printWithLeftPadding(backtrace[i].sym_call.substring(2), 12, "0");
					offset = "0x000000"
				}
				var name = backtrace[i].sym_name;
				console.log("FRAPL".frapl + ":  " + index.bt_sym_idx + " " + module.bt_mod_name + " " + base.bt_sym_addr + " + " + offset.bt_sym_addr + " " + name.bt_sym_name);
			}
			QueueSendNext();
			break;
		case kFridaLink_SetHookRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLInstallHook(inJSON.data);
			break;
		case kFridaLink_DelHookRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLRemoveHook(inJSON.data);
			break;
		case kFridaLink_UpdHookRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLUpdateHook(inJSON.data);
			break;
		case kFridaLink_SetReplaceRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLReplaceImpl(inJSON.data);
			break;
		case kFridaLink_DelReplaceRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLRevertImpl(inJSON.data);
			break;
		case kFridaLink_UpdReplaceRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLUpdateReplaceImpl(inJSON.data);
			break;
		case kFridaLink_AddMemRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLAddMemory(inJSON.data);
			break;
		case kFridaLink_DelMemRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLDelMemory(inJSON.data);
			break;
		case kFridaLink_FetchMemRequest:
			if (hasFridaLinkRPC)
				currentAPI.FrLFetchMemory(inJSON.data);
			break;
		case kFridaLink_ExecuteScript:
			if (hasFridaLinkRPC)
				currentAPI.FrLExecScript(inJSON.data);
			break;
		case kFridaLink_DebugContinue:
			currentScript.post({ type: inJSON.req_id });
			break;
	}
}

function HandleHookDumps(platform, response)
{
	var addr = "0x" + (response.address + 0x100000000).toString(16);
	var raddr = "(0x" + response.realAddr.toString(16) + "):";
	var mnem = response.mnemonic;
	console.log("FRAPL".frapl + ":", "--[".bt_graphic, "HOOK on", addr.bt_sym_addr, raddr.bt_sym_addr, mnem.bt_sym_name, "]".bt_graphic)

	// Dump registers
	if (response.cpu_ctx != null)
	{
		console.log("FRAPL".frapl + ":", platform.bt_sym_idx, "CPU registers".bt_sym_idx);
		var regList = "";
		var perRow = 4;
		for (reg in response.cpu_ctx)
		{
			var intValue = parseInt(response.cpu_ctx[reg], 16);
			var hexValue = "0x" + utils.printWithLeftPadding(intValue.toString(16), 12, "0");
			regName = utils.printWithLeftPadding(reg, 3, " ");
			regList += regName.bt_mod_name + " = " + hexValue.bt_sym_addr + "   ";
			perRow -= 1;
			if (perRow == 0)
			{
				console.log("FRAPL".frapl + ":    ", regList);
				perRow = 4;
				regList = "";
			}
		}
		if (regList != "")
			console.log("FRAPL".frapl + ":    ", regList);
	}
	
	// Dump memory
	if (response.memory != null)
	{

	}
}

function MessageListenerCore(message, data)
{
	var passThrough = false;

	if (message.type == 'error')
	{
		// Display server side error
		console.log('ERROR'.error + ': ' + GetErrorDetails(message));
		return;
	}

	switch (message.payload.id) 
	{
		case kMessageID_Info:
			console.log('FRAPL'.frapl + ': ' + message.payload.data);
			if (linkSocket != null)
			{
				var outData = { 
					req_id:		kFridaLink_FraplLogEntry, 
					log_type:	"info",
					log_entry:	message.payload.data
				};
				QueueSend(JSON.stringify(outData))
			}
			break;

		case kMessageID_Error:
			console.log('FRAPL'.error + ': ' + message.payload.data);
			if (linkSocket != null)
			{
				var outData = { 
					req_id:		kFridaLink_FraplLogEntry, 
					log_type:	"error",
					log_entry:	message.payload.data
				};
				QueueSend(JSON.stringify(outData))
			}
			break;

		case kMessageID_Pong:
			// Ping response received
			var pongMessage = message.payload.data;
			console.log('FRAPL'.frapl + ': <- pong(' +
				' recv = ' + pongMessage.data + ' ' +
				')');
			pingCount++;
			break;

		case kMessageID_Link:
			// Outgoing FridaLink message received
			if (linkSocket == null)
				break;

			var linkMessage = message.payload.data;
			switch (linkMessage.req_id) 
			{
				case kFridaLink_TargetInfo:
					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_ModulesResponse:
					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_ProcessBacktrace:
					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_HookResponse:
					if (linkMessage.response.count != 0)
					{
						// if (linkMessage.response.type == "inst")
						// {
						// 	HandleHookDumps(linkMessage.platform, linkMessage.response);
						// }

						delete linkMessage.response['address'];
						delete linkMessage.response['realAddr'];
						delete linkMessage.response['mnemonic'];
					}

					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_ReplaceResponse:
					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_FetchMemResponse:
					QueueSend(JSON.stringify(linkMessage))
					break;
				case kFridaLink_DBQuery:
					QueueSend(JSON.stringify(linkMessage))
					break;
			}
			break;

		case kMessageID_Reload:
			UpdateServerScript();
			break;

		case kMessageID_Stop:
			break;

		default:
			passThrough = true;
	}

	if (clientMessageListener != null && passThrough)
		clientMessageListener(message, data);

	if (message.payload['id'] == kMessageID_Stop)
	{
		// server is reasy to be shut down
		console.log('FRAPL'.frapl + ': stop()');

		// uninstall script
		UninstallServerScript(currentScript);
	}
}

function Init(args)
{
	// FIXME: implement proper parser
	for (i = 2; i < args.length; ++i) {
 		if (args[i] == "-c") {
			try {
				var theme = fs.readFileSync(args[i+1]);
				colors.setTheme(JSON.parse(theme.toString()));
			} catch (e) {
				console.log("ERROR".error + ": can not open base theme file");
			}
		}
	}

	for (i = 2; i < args.length; ++i) {
		if (args[i] == '-l') {
			autoLink = true;
			console.log("FRAPL".frapl + ": establish FridaLink automatically");
		} else if (args[i] == '-a') {
			autoResume = true;
			console.log("FRAPL".frapl + ": auto-resume target");
		} else if (args[i] == '-n') {
			startMode = kStartMode_AttachByName;
			startTarget = args[i + 1];
			console.log("FRAPL".frapl + ": starting mode set to", "attach by name".blue);
		} else if (args[i] == "-p") {
			startMode = kStartMode_AttachByPID;
			startTarget = args[i + 1];			
			console.log("FRAPL".frapl + ": starting mode set to", "attach by PID".blue);
		} else if (args[i] == "-s") {
			startMode = kStartMode_Spawn;
			startTarget = args[i + 1];
			console.log("FRAPL".frapl + ": starting mode set to", "spawn".blue);
		} else if (args[i] == "-b") {
			startBundleId = args[i + 1];
		} else if (args[i] == "-r") {
			startRemote = true
		}
	}

	console.log("FRAPL".frapl + ": target location set to", (startRemote)? "remote".blue : "local".blue);

	if (args.length < 5 || startTarget.length == 0) {
		console.log('Usage:'.yellow);
		console.log('-c'.green, "use theme file");
		console.log('-l'.green, "establish FridaLink automatically");
		console.log('-a'.green, "auto-resume target after spawn");
		console.log('Examples:'.yellow);
		console.log('1.'.green, 'node ./client.js -n', 'name'.green, './server.js', '// attach to local process by process name'.grey);
		console.log('2.'.green, 'node ./client.js -p', 'pid'.green, './server.js', '// attach to local process by PID'.grey);
		console.log('3.'.green, 'node ./client.js -s', 'path'.green, './server.js', '// spawn local process by path'.grey);
		console.log('4.'.green, 'node ./client.js -r -p', 'pid'.green, './server.js', '// attach to remote process by PID'.grey);
		console.log('5.'.green, 'node ./client.js -r -s', 'name'.green, '-b', 'bundle_id'.green, './server.js', '// spawn remote process by name and bundle id'.grey);
		process.exit();
	}

	serverScriptName = args[args.length-1];
}
exports.init = Init;

function GetStartMode () 
{
	return startMode;
}
exports.getStartMode = GetStartMode;

function GetStartTarget () 
{
	return startTarget;
}
exports.getStartTarget = GetStartTarget;

function GetServerScriptName () 
{
	return serverScriptName;
}
exports.getServerScriptName = GetServerScriptName;

function InstallServerScript(target, startMode, scriptSource, clientCode, messageListener, keyHandler)
{
	co(function *() {
		if (startRemote) {
			remoteDevice = yield frida.getUsbDevice();
		}

		if (startMode == kStartMode_AttachByName) {
			console.log('FRAPL'.frapl + ': attaching to target by name...');
			currentSession = yield frida.attach(target);
		}
		else if (startMode == kStartMode_AttachByPID) {
			console.log('FRAPL'.frapl + ': attaching to target by PID...');
			if (startRemote)
				currentSession = yield remoteDevice.attach(parseInt(target, 10));
			else
				currentSession = yield frida.attach(parseInt(target, 10));
		}
		else if (startMode == kStartMode_Spawn) {
			console.log('FRAPL'.frapl + ': spawn target app...');
			if (startRemote) {
				if (startBundleId == "") {
					var error = new Error("invalid BundleId (use " + "-b [bundle_id]".blue + " argument)")
					throw error
				}
				currentPID = yield remoteDevice.spawn([startBundleId]);
			}
			else {
				currentPID = yield frida.spawn([target]);
			}
			console.log('FRAPL'.frapl + ': attaching to target by PID ('+ currentPID +')...');
			currentSession = yield frida.attach(currentPID);
		}

		// Enable Duktape JavaScript Runtime
		currentSession.disableJit();  

		currentScript = yield currentSession.createScript(scriptSource);

		console.log('FRAPL'.frapl + ': server script created');
		// Set core message listener
		clientMessageListener = messageListener;
		currentScript.events.listen('message', MessageListenerCore);
		console.log('FRAPL'.frapl + ': message listener set');

		// Load script to target process
	  	yield currentScript.load()

		console.log('FRAPL'.frapl + ': server script loaded');
		currentAPI = yield currentScript.getExports();
		
		if (hasHelperLibRPC)
			yield currentAPI.FrALoadHelperLib();

		// Hook shortcuts
		process.stdin.setRawMode(true); 
		process.stdin.on('data', HandleShortcut(keyHandler));

		// Execute client code if any
		if (clientCode != null)
		{
			console.log('FRAPL'.frapl + ': executing client\'s code...');
			clientCode(currentScript);
		}

		// Setup FridaLink
		if (autoLink)
			SetupFridaLink();

		// Resume target for spawn start
		if (startMode == kStartMode_Spawn && autoResume)
		{
			console.log('FRAPL'.frapl + ': resuming target...');
			if (startRemote)
			 	remoteDevice.resume(currentPID);
			else
				frida.resume(currentPID);
		}
	})
	.catch(function (error) {
		console.log('ERROR'.error + ':', error.message);
	})
}
exports.installServerScript = InstallServerScript; 

function UpdateServerScript ()
{
	console.log('FRAPL'.frapl + ': **** UPDATING SERVER SCRIPT ****'.info);

	// stop message listener
	currentScript.events.unlisten('message', MessageListenerCore);
	
	// unload script from target process
	currentScript.unload()
	.then (function () {
		LoadScript(serverScriptName, function (scriptSource) {
			co(function *() {
			 	currentScript = yield currentSession.createScript(scriptSource);

				console.log('FRAPL'.frapl + ': server script created');
				// Set core message listener
				currentScript.events.listen('message', MessageListenerCore);
				console.log('FRAPL'.frapl + ': message listener set');

				// Load script to target process
	  			yield currentScript.load()

				console.log('FRAPL'.frapl + ': server script loaded');
			})
		});
	})	
}
exports.updateServerScript = UpdateServerScript; 

function UninstallServerScript(serverScript)
{
	if (linkSocket != null)
	{
		linkSocket.destroy();
		linkSocket = null;
	}

	// stop message listener
	clientMessageListener = null;
	serverScript.events.unlisten('message', MessageListenerCore);
	
	// unload script from target process
	serverScript.unload()
	.then (function () {
		currentSession.detach()
		.then (function () {
			console.log("FRAPL".frapl + ": detached");
			process.exit();
		})
	})
}
exports.uninstallServerScript = UninstallServerScript; 

function SetupFridaLink()
{
	try 
	{
		if (linkSocket == null)
		{
			linkSocket = new net.Socket();
			linkSocket.connect(LINK_PORT, LINK_HOST, function() {
				console.log("FRAPL".frapl + ": FridaLink established");
				if (hasFridaLinkRPC)
					currentAPI.FrLGetTargetInfo();
			});

			linkSocket.on('data', function(data) {
				var token = data.indexOf("}{")
				if (token > -1)
				{
					var jsonArray = JSON.parse("[" + data.toString().replace(/\}\{/g, "},{") + "]");
					for (var index in jsonArray)
					{
						HandleLinkResponse(jsonArray[index]);
					}
				}
				else
				{
					HandleLinkResponse(JSON.parse(data));
				}
			});

			linkSocket.on('close', function() {
				console.log("FRAPL".frapl + ": FridaLink disconnected");
				if (linkSocket != null)
				{
					linkSocket.destroy();
					linkSocket = null;
					console.log("FRAPL".frapl + ": FridaLink closed");
				}
			});

			linkSocket.on('error', function(err) {
				console.log("ERROR".error + ": FridaLink error (" + err.message + ")");
				linkSocket.destroy();
				linkSocket = null;
			})
		}
		else
		{
			linkSocket.destroy();
			linkSocket = null;

			console.log("FRAPL".frapl + ": FridaLink closed");
		}
	} 
	catch (e)
	{
		console.log("ERROR".error + ": can not establish FridaLink" + e);
	}
}

// *** Utils

function HandleShortcut (clientKeyHandler) 
{
	return function(data)
	{
		switch (data[0]) 
		{
			case kShortCut_CtrlR:
				currentScript.post({ id: kMessageID_Reload });
				break;

			case kShortCut_CtrlS:
				// Resume target for spawn start
				if (startMode == kStartMode_Spawn)
				{
					console.log('FRAPL'.frapl + ': resuming target...');
					if (startRemote)
					 	remoteDevice.resume(currentPID);
					else
						frida.resume(currentPID);
				}
				break;

			case kShortCut_CtrlC:
				if (hasFridaLinkRPC)
					currentAPI.FrLCleanup();
				currentScript.post({ id: kMessageID_Stop });
				break;

			case kShortCut_CtrlL:
				SetupFridaLink();
				break;

			case kShortCut_CtrlP:
				console.log('FRAPL'.frapl + ': -> ping(' +
					' sent = ' + pingCount + ' ' +
					')');

		  		currentScript.post({ id: kMessageID_Ping , data: pingCount });
				break;

			case kShortCut_CtrlZ:
				console.log("FRAPL".frapl + ": forced quit");
				process.exit();

			default:
				if (clientKeyHandler != null)
					clientKeyHandler(data);
		}		
    }
}

function include(fileName) {
    with (global) {
    	const fs = require('fs');
    	eval.apply(global, [fs.readFileSync(fileName).toString()]);
    };
};
exports.include = include; 

function GetCurrentSession ()
{
	return currentSession;
}
exports.getCurrentSession = GetCurrentSession; 

function GetCurrentScript ()
{
	return currentScript;
}
exports.getCurrentScript = GetCurrentScript; 

function GetErrorDetails(errorMessage)
{
	const description = errorMessage.description;
	var line = errorMessage.lineNumber;

	for (var includePath in dbgIncludeList)
	{
		var includeDesc = dbgIncludeList[includePath];

		if (line > includeDesc.start && line < includeDesc.end)
		{
			return description + "\n" + 
				"[ " + includePath + " ]:\n" +
				"  ..." + "\n" +
				"  " + utils.printWithLeftPadding(line-includeDesc.start-1, 3) + ": " + dbgSourceLines[line-2] + "\n" + 
				"> " + utils.printWithLeftPadding(line-includeDesc.start-0, 3) + ": " + dbgSourceLines[line-1] + "\n" + 
				"  " + utils.printWithLeftPadding(line-includeDesc.start+1, 3) + ": " + dbgSourceLines[line] + "\n" + 
				"  ..." + "\n";
		}
	}

	return JSON.stringify(errorMessage);
}
exports.getErrorDetails = GetErrorDetails; 

function LoadScript(fileName, readyCallback)
{
	var script;
	co(function *(){
		const data = fs.readFileSync(fileName);
		var baseScript = data.toString();
	
		// Bind RPC

		var rpc_export = "\n";

		if(baseScript.indexOf("FRAPL/FrACommon.js") == -1)
		{
			console.log("FRAPL".frapl + ": unable to find " + "FrACommon.js".file + ", fixed.");
			baseScript = "include('FRAPL/FrACommon.js');\n" + baseScript;
		}

		if(baseScript.indexOf("FRAPL/FrAServerCore.js") == -1)
		{
			console.log("FRAPL".frapl + ": unable to find " + "FrACommon.js".file + ", fixed.");
			baseScript = "include('FRAPL/FrAServerCore.js');\n" + baseScript;
		}

		if(baseScript.indexOf("FRAPL/FrAHelperLib.js") > -1)
		{	
			console.log("FRAPL".frapl + ": bind export from " + "FrAHelperLib.js".file);
			rpc_export += "rpc.exports[\"FrALoadHelperLib\"] = FrALoadHelperLib;\n";
			hasHelperLibRPC = true;
		}

		if(baseScript.indexOf("FRAPL/FrAFridaLink.js") > -1)
		{	
			console.log("FRAPL".frapl + ": bind export from " + "FrAFridaLink.js".file);
			rpc_export += 
				"rpc.exports[\"FrLGetTargetInfo\"] = FrLGetTargetInfo;\n" + 
				"rpc.exports[\"FrLRequestModules\"] = FrLRequestModules;\n" + 
				"rpc.exports[\"FrLInstallHook\"] = FrLInstallHook;\n" + 
				"rpc.exports[\"FrLRemoveHook\"] = FrLRemoveHook;\n" +
				"rpc.exports[\"FrLUpdateHook\"] = FrLUpdateHook;\n" + 
				"rpc.exports[\"FrLReplaceImpl\"] = FrLReplaceImpl;\n" + 
				"rpc.exports[\"FrLRevertImpl\"] = FrLRevertImpl;\n" +
				"rpc.exports[\"FrLUpdateReplaceImpl\"] = FrLUpdateReplaceImpl;\n" + 
				"rpc.exports[\"FrLAddMemory\"] = FrLAddMemory;\n" + 
				"rpc.exports[\"FrLDelMemory\"] = FrLDelMemory;\n" + 
				"rpc.exports[\"FrLFetchMemory\"] = FrLFetchMemory;\n" + 
				"rpc.exports[\"FrLExecScript\"] = FrLExecScript;\n" + 
				"rpc.exports[\"FrLCleanup\"] = FrLCleanup;\n" + 
				"\n";
			hasFridaLinkRPC = true;
		}

		baseScript += rpc_export;

		// create temporary file in framework folder
		const baseScriptPath = __dirname + "/../" + uuid.v4() + ".js";
		fs.writeFileSync(baseScriptPath, baseScript);

		// load script using frida-load
		script = yield load(require.resolve(baseScriptPath));
		console.log("FRAPL".frapl + ": script source is loaded");

		// handle include directives
		console.log("FRAPL".frapl + ": process 'include' directives");
		dbgSourceLines = 0;
		var rePattern = new RegExp(/^include *\( *\'(.*)\' *\)\;$/gm);
		var headerSize = 0;
		var lastIncludeLine = 0
		while (matches = rePattern.exec(script)) {
			var extension;
			try {
				extension = fs.readFileSync(matches[1]);
				var start = script.substring(0, matches.index).split("\n").length;
				var end = start + (extension.toString().split("\n").length + 1);
				if (headerSize == 0)
					headerSize = start;
				else
					headerSize++;
				lastIncludeLine = end;
				dbgIncludeList[matches[1]] = {start, end};
			} catch (e) {
				console.log("ERROR".error + ": can not open extension file: \'" + matches[1] + "\'");
				return;
			}

			console.log("FRAPL".frapl + ":   " + "include".include + "(\'" +  matches[1].file + "\')");
			script = script.replace(matches[0], "\n" + extension.toString() + "\n");
		}

		// delete temporary file
		fs.unlinkSync(baseScriptPath);

	}).then(function () {
 		readyCallback(script);
	}).catch(function (err) {
 		console.error(err.stack);
	});
}
exports.loadScript = LoadScript;

function RunServerScript(clientCode, messageListener, keyHandler)
{
	LoadScript(serverScriptName, function (scriptSource) {
		InstallServerScript(startTarget, startMode, scriptSource, clientCode, messageListener, keyHandler);
	});
}
exports.runServerScript = RunServerScript; 
