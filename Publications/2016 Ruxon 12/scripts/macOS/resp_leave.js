if (this.readStream != null && this.readStream in FrlGlobal['iTunes'].handlers)
{
	if (retval !== null)
	{
		FraplLog("CFReadStreamCopyProperty: leave (property = " + retval + ")");

		var cfData = CFHTTPMessageCopySerializedMessage(retval); 
		var resp_data = CFDataToUTF8String(cfData);
		if (resp_data !== null) 
		{
			var sql_query = 
				"INSERT OR REPLACE INTO transactions (req_id, time, req_data, resp_data) VALUES (\n" +
				"	\"" + ptr(this.readStream) + "\",\n" + 
				"	COALESCE((SELECT time FROM transactions WHERE req_id = \"" + ptr(this.readStream) + "\"), CURRENT_TIMESTAMP),\n" +
				"	(SELECT req_data FROM transactions WHERE req_id = \"" + ptr(this.readStream) + "\"),\n" +
				"	\"" + resp_data.replace(/"/g, '\'\'') + "\"\n" +
				");"
			
			FrLExecQuery("iTunes_macOS", sql_query);
		}
	}
}
