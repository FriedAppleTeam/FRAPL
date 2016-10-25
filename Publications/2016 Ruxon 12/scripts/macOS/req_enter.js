// CFReadStreamRef CFReadStreamCreateForHTTPRequest ( CFAllocatorRef alloc, CFHTTPMessageRef request );

FraplLog("CFReadStreamCreateForHTTPRequest: enter");

var request = args[1];
this.requestData = CFHTTPMessageCopySerializedMessage(request);

