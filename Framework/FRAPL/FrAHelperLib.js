//
// FrAHelperLib.js
// Fried Apple Framework
//
// Created by Alexander Hude on 16/01/16.
// Copyright (c) 2016 FriedApple. All rights reserved.
//

const FrAHelperLibName = "frapl-helper.dylib"
var FrAHelperLibHandle = 0x0;

var _frapl_self_test = 0x0

function FrALoadHelperLib()
{
	// import dlopen() locally, because global one may be not ready yet
	const _RTLD_NOW     = 0x2;
	const _obj_dlopen = Module.findExportByName("libdyld.dylib", "dlopen");
	const _dlopen = new NativeFunction(_obj_dlopen, "pointer", ["pointer", "int"]);

	FrAHelperLibHandle = _dlopen(Memory.allocUtf8String(FrAHelperLibName), _RTLD_NOW);
	if (FrAHelperLibHandle == 0x0)
	{
		// App is probably sanboxed, library should be placed next to main binary

		// import dyld_get_image_name() locally, because global one may be not ready yet
		const _obj_dyld_get_image_name = Module.findExportByName("libdyld.dylib", "_dyld_get_image_name");
		const _dyld_get_image_name = new NativeFunction(_obj_dyld_get_image_name, "pointer", ["int"]);

		var binaryPath = Memory.readCString(_dyld_get_image_name(0));
		binaryPath = binaryPath.substring(0, binaryPath.lastIndexOf('/')+1) + FrAHelperLibName;
		FrAHelperLibHandle = _dlopen(Memory.allocUtf8String(binaryPath), _RTLD_NOW);
	}

	if (FrAHelperLibHandle == 0x0)
	{
		send({ id: kMessageID_Error , data: "Unable to load '" + FrAHelperLibName + "'" });		
		return;
	}

	// *** SELF TEST
	const _object_self_test = Module.findExportByName(FrAHelperLibName, "self_test");
	_frapl_self_test = new NativeFunction(_object_self_test, "int", ["int"]);

	const magic_req = Math.floor((Math.random() * 1000) + 1);
	const magic_ret = _frapl_self_test(magic_req);
	if (magic_ret != (magic_req * 2))
	{
		send({ id: kMessageID_Error , data: "Unable to use '" + FrAHelperLibName + "' (" + magic_req + " != " + magic_ret + ")"});		
		return;
	}

	send({ id: kMessageID_Info , data: "Frapl HelperLib Loaded" });
}

function FraplCloseHelper()
{
	if (FrAHelperLibHandle != 0x0)
	{
		// import dlclose() locally, because global one may be not ready yet
		const _obj_dlclose = Module.findExportByName("libdyld.dylib", "dlclose");
		const _dlclose = new NativeFunction(_obj_dlclose, "int", ["pointer"]);

		var res = _dlclose(FrAHelperLibHandle);
		send({ id: kMessageID_Info , data: "'" + FrAHelperLibName + "' closed with (" + res + ")" });	
		FrAHelperLibHandle = 0x0;
	}
}

function FraplSelfTest(value)
{
	if (_frapl_self_test != 0x0)
	 	return _frapl_self_test(value);
}
