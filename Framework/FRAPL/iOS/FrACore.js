//
// FrACore.js (iOS)
// Fried Apple Framework
//
// Created by Alexander Hude on 31/06/16.
// Copyright (c) 2016 FriedApple. All rights reserved.
//

// *** Core Foundation

const CFRelease = ResolveImportSymbol("CoreFoundation", "CFRelease", "pointer", ["pointer"]);

const CFDataGetBytePtr = ResolveImportSymbol("CoreFoundation", "CFDataGetBytePtr", "pointer", ["pointer"]);

function CFDataToUTF8String(cfData) {
	if (cfData !== null)
		return Memory.readUtf8String(CFDataGetBytePtr(cfData)).toString();
	else
		return "";
}
