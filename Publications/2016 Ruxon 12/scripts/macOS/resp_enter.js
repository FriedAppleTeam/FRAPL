// CFTypeRef CFReadStreamCopyProperty ( CFReadStreamRef stream, CFStringRef propertyName );

this.readStream = null
if (args[0] in FrlGlobal['iTunes'].handlers)
{
	var propertyName = ObjC.Object(args[1]).UTF8String();
	if (propertyName == "kCFStreamPropertyHTTPResponseHeader")
	{
		this.readStream = args[0]

		FraplLog("CFReadStreamCopyProperty: enter (stream = " + this.readStream.toString() + ")");
	}
}
