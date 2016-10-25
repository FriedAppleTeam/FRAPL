if (this.requestData !== null)
{
	FraplLog("CFReadStreamCreateForHTTPRequest: leave (stream = " + retval + ")");

	FrlGlobal['iTunes'].handlers[retval] = true;

	var req_str = CFDataToUTF8String(this.requestData);
	if (req_str !== null)
	{
		var sql_query = 
			"INSERT OR REPLACE INTO transactions (req_id, time, req_data, resp_data) VALUES (\n" +
			"	\"" + ptr(retval) + "\",\n" + 
			"	COALESCE((SELECT time FROM transactions WHERE req_id = \"" + ptr(retval) + "\"), CURRENT_TIMESTAMP),\n" +
			"	\"" + req_str.replace(/"/g, '\'\'') + "\",\n" +
			"	(SELECT resp_data FROM transactions WHERE req_id = \"" + ptr(retval) + "\")\n" +
			");"

		FrLExecQuery("iTunes_macOS", sql_query);
	}
}
