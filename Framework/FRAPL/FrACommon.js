//
// FrACommon.js
// Fried Apple Framework
//
// Created by Alexander Hude on 16/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

// *** Start modes

var kStartMode_Undefined 		= -1;
var kStartMode_AttachByName		= 0;
var kStartMode_AttachByPID 		= 1;
var kStartMode_Spawn 			= 2;

// *** Shortcuts

var kShortCut_CtrlR		= 18;	// CTRL+R - reload
var kShortCut_CtrlS		= 19;	// CTRL+S - start/resume
var kShortCut_CtrlC		= 3;	// CTRL+C - exit
var kShortCut_CtrlL		= 12;	// CTRL+L - link
var kShortCut_CtrlP		= 16;	// CTRL+P - ping
var kShortCut_CtrlZ		= 26;	// CTRL+Z - force quit

// *** CLIENT/SERVER MESSAGE IDs

var kMessageID_Ping	= "fra_ping";
var kMessageID_Pong	= "fra_pong";
var kMessageID_Info	= "fra_info";
var kMessageID_Error	= "fra_error";
var kMessageID_Link	= "fra_link";
var kMessageID_Reload	= "fra_reload";
var kMessageID_Stop	= "fra_stop";
