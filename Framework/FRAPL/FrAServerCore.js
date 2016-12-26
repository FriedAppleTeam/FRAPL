//
// FrAServerCore.js
// Fried Apple Framework
//
// Created by Alexander Hude on 09/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

// *** Message receiver

function onMessage(message) 
{
	var reload = false;

	switch (message['id']) 
	{
		case kMessageID_Ping:
			send({ id: kMessageID_Pong, data: message });
			break;

		case kMessageID_Reload:
			message['id'] = kMessageID_Stop
			reload = true;
			break;

		default:
			break;
	}

	handleMessage(message);

	if (message['id'] == kMessageID_Stop)
	{
		send({ id: (reload)? kMessageID_Reload : kMessageID_Stop, data: message });
	}

	recv(onMessage);
}

recv(onMessage);
