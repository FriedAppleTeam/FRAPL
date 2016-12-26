//
// server.js
// 

include('FRAPL/FrACommon.js');
include('FRAPL/FrAServerCore.js');

// *** RPC setup

rpc.exports = {
	// Your RPC exports here
	// your_rpc_call() { },
};

// *** Incoming Message Hanlder

function handleMessage(message) 
{	
	switch (message['id']) 
	{
	//	case "your_message_id":
	//		break;

		case kMessageID_Stop:
			// Restore original state
			break;

		default:
			break;
	}
}
