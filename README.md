# Fried Apple Framework (FRAPL)

__FRAPL__ is a reverse engineering framework created to simplify dynamic instrumentation with __Frida__. 

The core of __FRAPL__ is __FridaLink__ - TCP/JSON based protocol and IDA plugin for establishing a bridge between __Frida__ client and __IDA Pro__. It brings runtime information to IDA disassembly and allows monitoring dynamic changes by controlling __Frida__ directly from __IDA__. 

__FRAPL__ requires just three simple steps to actually start reverse engineering. Without a single line of code. 

This is a new way of combining static and dynamic analysis. 

<center>__FridaLink Overall View__</center>
![FRAPL](./Resources/screenshots/frapl_overall_view.png?raw=true "FRAPL")

<center>You can find old FridaLink User Manual [here](./Resources/documents/FridaLinkUserManual_160412.pdf)</center>

## Publications

### Ruxcon 12 (October 2016)

&nbsp;&nbsp;&nbsp;[Presentation](https://ruxcon.org.au/speakers/#Alex%20Hude%20&%20Max%20Bazaliy)

&nbsp;&nbsp;&nbsp;[Slides](./Publications/2016 Ruxon 12/Ruxcon_12_FRAPL.pdf)   

&nbsp;&nbsp;&nbsp;[iOS Demo](https://www.youtube.com/watch?v=SLlX4aPbUUk)   
&nbsp;&nbsp;&nbsp;[macOS Demo](https://www.youtube.com/watch?v=V1bR-5uXC_M)

## Design and Structure

### SOURCE CODE

&nbsp;&nbsp;&nbsp;**COMING SOON (end of 2016)**

### FRAPL

* __iOS/*__ - iOS specific FRAPL headers (classes, helpers, UI)
* __macOS/*__ - macOS specific FRAPL headers (classes, helpers, UI)
* __FrAClientCore.js__ - Node.js Frida client core
	* Client script (with `include()` command support)
	* Executing server script on target
	* Frida RPC client/server message handling (client side)
	* FridaLink message handling (from Frida server and from/to IDA)
	* Shortcut handling
* __FrAServerCore.js__ - JS Frida server core
	* Frida RPC client/server message handling (server side)
* __FrAHelperLib.js__ - JS code to communicate with FRAPL Helper Library
* __FrAFridaLink.js__ - JS Frida server functions for FridaLink
* __FrACommon.js__ - Node.js/JS code to share between Frida client and server
* __FrAGCD.js__ - JS code to add Grand Central Dispatch support to Frida server
* __FrAdlfcn.js__ - JS code to add dl* funtions support from libdyld.dylib
* __FrAUtils.js__ - Node.js/JS utility functions to share between Frida client and server
	* Algorithms
	* Output formatting
	* Dumpers (like memory and ObjC)
	* Other helper functions

### FridaLink
* __FridaLink/__ - FridaLink Source Code
* __FridaLink.py__ - IDA Pro script (will be a plugin eventually) to implement FridaLink server


### Misc
* __package.json__ - nmp package description to install all dependencies
* __create_project.sh__ - Script for generating minimal scripts for FRAPL and FridaLink
* __README.md__ - this readme file

### Architecture

![Architecture](./Resources/screenshots/frapl_architecture.png?raw=true "Architecture")

## Getting Started

### Prerequisites

To install required nmp modules run following command in __FRAPL__ folder:   
`$ nmp install`

### FridaLink

**FridaLink** setup is **as simple as 1-2-3** and requires just three steps to actually start reverse engineering your target. Without a single line of code.  

1. In IDA press __ALT+F7__ and load __FridaLink.py__  
2. In terminal run `$ ./create_project.sh -f ~/Projects/TargetApp ; cd ~/Projects/TargetApp` to create project  
3. In terminal to attach to target and establish FridaLink run  
`$ node ./client.js -l -n TargetApp server.js` for macOS target  
`$ node ./client.js -l -r -p $(frida-ps -U | grep TargetApp | awk '{print $1}') ./server.js` for iOS target
