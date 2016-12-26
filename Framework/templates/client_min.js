//
// client.js
//

const FRAPL = require('./FRAPL/FrAClientCore.js');

FRAPL.include('./FRAPL/FrACommon.js');

FRAPL.init(process.argv);

// *** Message Listener

function MessageListener(message, data) 
{
	if (message.type == 'error')
	{
		// Display server side error
		console.log('ERROR: ' + FRAPL.getErrorDetails(message));
		return;
	}

	switch (message.payload['id']) 
	{
	// 	case YourCase:
	//		break;

		case kMessageID_Stop:
			// server is ready to be shut down
			break;

		default:
			console.log("CLIENT: unknown( " + message + " )");
			break;
	}
}

// *** Key Handler

function KeyHandler (data)
{
	// Your key handlers here
	// if (data[0] == [key_code])
	// 	...
}

// *** Client Code

function ClientCode (serverScript)
{
	// Your client code here
}

// 1. Separate load and install

// function scriptSourceReadyCallback (scriptSource) {
// 	FRAPL.installServerScript(FRAPL.getStartTarget(), FRAPL.getStartMode(), scriptSource, ClientCode, MessageListener, KeyHandler);
// }

// FRAPL.loadScript(FRAPL.getServerScriptName(), scriptSourceReadyCallback);

// 2. All-in-one

FRAPL.runServerScript(ClientCode, MessageListener, KeyHandler);
