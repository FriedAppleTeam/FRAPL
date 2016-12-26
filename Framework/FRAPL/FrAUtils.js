//
// FrAUtils.js
// Fried Apple Framework
//
// Created by Alexander Hude on 11/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

// *** Algorithm

function BinaryIndexOf(array, searchElement, fuzzy) 
{
    'use strict';
 
    fuzzy = typeof fuzzy !== 'undefined' ? fuzzy : false;

    var minIndex = 0;
    var maxIndex = array.length - 1;
    var currentIndex;
    var currentElement;
 
    while (minIndex <= maxIndex) 
    {
        currentIndex = (minIndex + maxIndex) / 2 | 0;
        currentElement = array[currentIndex];
 
        if (currentElement < searchElement) 
        {
            minIndex = currentIndex + 1;
        }
        else if (currentElement > searchElement) 
        {
            maxIndex = currentIndex - 1;
        }
        else 
        {
            return currentIndex;
        }
    }
 	
 	if (fuzzy)
	    return currentIndex;
	else
		return -1;
}

// *** Formatting

function PrintWithLeftPadding(value, padding, symbol) 
{
	symbol = typeof symbol !== 'undefined' ? symbol : " ";

	var pad = Array(padding).join(symbol);
	return String(pad + value.toString()).slice(-padding);
}

function PrintWithRightPadding(value, padding, symbol) 
{
    symbol = typeof symbol !== 'undefined' ? symbol : " ";

    var pad = Array(padding - value.toString().length).join(symbol);
    return String(value.toString() + pad);
}

function UintArrayToHex(ua, prefix) 
{
    prefix = typeof prefix !== 'undefined' ? prefix : "";

    var h = prefix;
    for (var i = 0; i < ua.length; i++) 
    {
    	if (i%16 == 0 && i != 0)
    		h += ("\n" + prefix);
        h += PrintWithLeftPadding(ua[i].toString(16), 2, "0") + " ";
    }
    return h;
}

// *** MISС

var gTargetOS = "unset";

function GetWordSize()
{
    var arch = Process.arch;
    if (arch == "x64" || arch == "arm64")
        return 8;
    else
        return 4;
}

function GetTargetOS()
{
    if (gTargetOS == "unset")
    {
        const desc = Process.platform + "_" + Process.arch;

        var rePattern = new RegExp(/^Version ([0-9]+\.[0-9]+(\.[0-9]+)?) \(Build ([0-9A-Z]+)\)$/gm);
        var matches = rePattern.exec(ObjC.classes.NSProcessInfo.processInfo().operatingSystemVersionString().UTF8String());
        const version = matches[1];
        const build = matches[3];

        switch(desc)
        {
            case "darwin_arm":
            case "darwin_arm64":
                gTargetOS = "iOS " + version + " (" + build + ")";
                break;

            case "darwin_ia32":
            case "darwin_x64":
                gTargetOS = "OSX " + version + " (" + build + ")";
                break;

            default:
                send({ id: kMessageID_Error, data: "Unknown OS: " + ObjC.classes.NSProcessInfo.processInfo().operatingSystemVersionString() });
                gTargetOS = "unknown";
        }
    }

    return gTargetOS;
}

function GetSortedKeys(map)
{
    var keys = Object.keys(map);
    keys.sort();

    return keys;
}

function DumpMemoryBytes(address, length, prefix)
{
    var memory = new Uint8Array(Memory.readByteArray(address, length));
    console.log(UintArrayToHex(memory, prefix));
}

function DumpObjcClassMethods(outputCallback, objcClassName)
{
    var dump_methods = function(objcClassKey)
    {
        var objcClass = ObjC.classes[objcClassKey];

        var protocolMethods = [];
        for (var protocol in objcClass.$protocols) 
        {
            for (var protocolMethod in objcClass.$protocols[protocol].methods)
            {
                protocolMethods[protocolMethod] = protocol;
            }
        }

        for (var methodIdx in objcClass.$methods) 
        {
            var method = objcClass.$methods[methodIdx];
            var address = null;
            try 
            {
                address = objcClass[method].implementation;

            } 
            catch (e) 
            {
                // ERROR: Cant get implementation address;
            }

            if (address != null)
            {
                var protocolName = "";
                if (method in protocolMethods)
                    protocolName = "(" + protocolMethods[method] + ")";
                var methodName = method[0] + "[" + objcClassKey + method.substring(1) + "] " + protocolName; 
                outputCallback(objcClassKey, address, methodName);
            }
        }
    }

    if (typeof objcClassName === 'undefined')
    {
        for (var objcClassKey in ObjC.classes) {
            
            outputCallback(objcClassKey, 0, "");

            dump_methods(objcClassKey);
        }
    }
    else
    {
        dump_methods(objcClassName);
    }
}

function ResolveImportSymbol(module, symbol, ret, args)
{
    ret = typeof ret !== 'undefined' ? ret : null;
    args = typeof args !== 'undefined' ? args : null;

    var sym_id = module + "-" + symbol;
    if (sym_id in ResolveImportSymbol.imports)
    {
        return ResolveImportSymbol.imports[sym_id];
    }

    var symbolPtr = Module.findExportByName(module, symbol);
    if (ret != null && args != null)
    {
        var symFunc = new NativeFunction(symbolPtr, ret, args);
        ResolveImportSymbol.imports[sym_id] = symFunc;
        return symFunc;
    }
    else
    {
        var symData = Memory.readPointer(symbolPtr);
        ResolveImportSymbol.imports[sym_id] = symData;
        return symData;
    }

    return null;    
}

ResolveImportSymbol.imports = {};

function FraplLog(logEntry)
{
    send({ id: kMessageID_Info , data: logEntry });
}

function FraplError(logEntry)
{
    send({ id: kMessageID_Error , data: logEntry });
}

// *** Node.js export

(function(exports) {

	// Algorithm
	exports.binaryIndexOf = BinaryIndexOf;

	// Formatting
	exports.printWithLeftPadding = PrintWithLeftPadding;
    exports.printWithRightPadding = PrintWithRightPadding;
	exports.UintArrayToHex = UintArrayToHex;

    // Misc
    exports.getSortedKeys = GetSortedKeys;    

})(typeof exports === 'undefined'? this.FrAUtils={} : exports );
