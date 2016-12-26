//
// FrANetwork.js (iOS)
// Fried Apple Framework
//
// Created by Alexander Hude on 31/06/16.
// Copyright (c) 2016 FriedApple. All rights reserved.
//

// *** CFNetwork

const CFHTTPMessageCopySerializedMessage = ResolveImportSymbol("CFNetwork", "CFHTTPMessageCopySerializedMessage", "pointer", ["pointer"]);
const CFHTTPMessageCreateRequest = ResolveImportSymbol("CFNetwork", "CFHTTPMessageCreateRequest", "pointer", ["pointer", "pointer", "pointer", "pointer"]);
const CFHTTPMessageCreateResponse = ResolveImportSymbol("CFNetwork", "CFHTTPMessageCreateResponse", "pointer", ["pointer", "long", "pointer", "pointer"]);
const CFHTTPMessageSetHeaderFieldValue = ResolveImportSymbol("CFNetwork", "CFHTTPMessageSetHeaderFieldValue", "pointer", ["pointer", "pointer", "pointer"]);
const CFHTTPMessageSetBody = ResolveImportSymbol("CFNetwork", "CFHTTPMessageSetBody", "pointer", ["pointer", "pointer"]);

const kCFHTTPVersion1_1 = new ObjC.Object(ResolveImportSymbol("CFNetwork", "kCFHTTPVersion1_1"));

// return: CFData
function NSURLRequestSerialize(request) {
	var message = CFHTTPMessageCreateRequest(NULL, request.HTTPMethod(), request.URL(), kCFHTTPVersion1_1);

	var dict = request.allHTTPHeaderFields();
	var enumerator = dict.keyEnumerator();
	var key;
	while ((key = enumerator.nextObject()) !== null) {
		CFHTTPMessageSetHeaderFieldValue(message, key, dict.objectForKey_(key));
	}

	if (request.HTTPBody() !== null)
		CFHTTPMessageSetBody(message, request.HTTPBody());

	var ret = CFHTTPMessageCopySerializedMessage(message);
	CFRelease(message);
	
	return ret;
}

// return: CFData
function NSURLResponseSerialize(response) {
	var message = CFHTTPMessageCreateResponse(NULL, response.statusCode(), NULL, kCFHTTPVersion1_1);

	var dict = response.allHeaderFields();
	var enumerator = dict.keyEnumerator();
	var key;
	while ((key = enumerator.nextObject()) !== null) {
		CFHTTPMessageSetHeaderFieldValue(message, key, dict.objectForKey_(key));
	}

	var ret = CFHTTPMessageCopySerializedMessage(message);
	CFRelease(message);
	
	return ret;
}
