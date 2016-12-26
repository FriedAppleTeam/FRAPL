//
// FrAGCD.js
// Fried Apple Framework
//
// Created by Alexander Hude on 09/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

const DISPATCH_QUEUE_PRIORITY_HIGH 			= 2;
const DISPATCH_QUEUE_PRIORITY_DEFAULT 		= 0;
const DISPATCH_QUEUE_PRIORITY_LOW 			= -2;
const DISPATCH_QUEUE_PRIORITY_BACKGROUND	= -32768;

const DISPATCH_QUEUE_SERIAL					= ptr(0);

const QOS_CLASS_USER_INTERACTIVE 			= 0x21;
const QOS_CLASS_USER_INITIATED 				= 0x19;
const QOS_CLASS_DEFAULT 					= 0x15;
const QOS_CLASS_UTILITY 					= 0x11;
const QOS_CLASS_BACKGROUND 					= 0x09;
const QOS_CLASS_UNSPECIFIED 				= 0x00;

const _object_getGlobalQueue = Module.findExportByName("libdispatch.dylib", "dispatch_get_global_queue");
const dispatch_get_global_queue = new NativeFunction(_object_getGlobalQueue, "pointer", ["int", "int"]);

const _object_getCurrentQueue = Module.findExportByName("libdispatch.dylib", "dispatch_get_current_queue");
const dispatch_get_current_queue = new NativeFunction(_object_getCurrentQueue, "pointer", ["void"]);

const _object_queueAttrMakeWithQosClass = Module.findExportByName("libdispatch.dylib", "dispatch_queue_attr_make_with_qos_class");
const dispatch_queue_attr_make_with_qos_class = new NativeFunction(_object_queueAttrMakeWithQosClass, "pointer", ["pointer", "int", "int"]);

const _object_QueueCreate = Module.findExportByName("libdispatch.dylib", "dispatch_queue_create");
const dispatch_queue_create = new NativeFunction(_object_QueueCreate, "pointer", ["pointer", "pointer"]);

const _object_dispatch_sync_f = Module.findExportByName("libdispatch.dylib", "dispatch_sync_f");
const dispatch_sync_f = new NativeFunction(_object_dispatch_sync_f, "void", ['pointer', 'pointer', 'pointer'])

function schedule_sync(queue, work) 
{
	const NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;
	const workCallback = new NativeCallback(function () {
	    const pool = NSAutoreleasePool.alloc().init();
	    var pendingException = null;
	    try {
	        work();
	    } catch (e) {
	        pendingException = e;
	    }
	    pool.release();
	    if (pendingException !== null) {
	        throw pendingException;
	    }
	}, 'void', ['pointer']);
	dispatch_sync_f(queue, NULL, workCallback);
};

var fraMainQueueAttr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_BACKGROUND, -1);
var fraMainQueue = dispatch_queue_create(Memory.allocUtf8String("com.FriedApple.MainQueue"), fraMainQueueAttr);
