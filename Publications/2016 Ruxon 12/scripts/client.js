//
// client.js
// Frida Client for FridaLink
//

const FRAPL = require('./FRAPL/FrAClientCore.js');

FRAPL.include('./FRAPL/FrACommon.js');

FRAPL.init(process.argv);

FRAPL.runServerScript(null, null, null);
