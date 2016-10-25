// -[ISURLOperation connection:didReceiveResponse:]

FraplLog("-[ISURLOperation connection:didReceiveResponse:]: enter (connection = " + args[2] + ")");

var connection = new ObjC.Object(args[2]); // NSURLConnection
var request = connection.currentRequest();
var req_data = NSURLRequestSerialize(request);
var req_str = CFDataToUTF8String(req_data);
if (req_str !== null)
{
	var sql_query = 
	"INSERT OR REPLACE INTO transactions (req_id, time, req_data, resp_data) VALUES (\n" +
	"	\"" + ptr(connection) + "\",\n" + 
	"	COALESCE((SELECT time FROM transactions WHERE req_id = \"" + ptr(connection) + "\"), CURRENT_TIMESTAMP),\n" +
	"	\"" + req_str.replace(/"/g, '\'\'') + "\",\n" +
	"	(SELECT resp_data FROM transactions WHERE req_id = \"" + ptr(connection) + "\")\n" +
	");"

	FrLExecQuery("iTunes_iOS", sql_query);
}

var response = new ObjC.Object(args[3]); // NSURLResponse
var resp_data = NSURLResponseSerialize(response);
var resp_str = CFDataToUTF8String(resp_data);
if (resp_str !== null)
{
	var sql_query = 
		"INSERT OR REPLACE INTO transactions (req_id, time, req_data, resp_data) VALUES (\n" +
		"	\"" + ptr(connection) + "\",\n" + 
		"	COALESCE((SELECT time FROM transactions WHERE req_id = \"" + ptr(connection) + "\"), CURRENT_TIMESTAMP),\n" +
		"	(SELECT req_data FROM transactions WHERE req_id = \"" + ptr(connection) + "\"),\n" +
		"	\"" + resp_str.replace(/"/g, '\'\'') + "\"\n" +
		");"
	
	FrLExecQuery("iTunes_iOS", sql_query);
}
