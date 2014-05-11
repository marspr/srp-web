/**
 * WebSocket Server with SRP authentication on Node.js. Requires
 * [node.js/api/crypto]{@link http://nodejs.org/api/crypto.html},
 * [jsbn]{@link https://www.npmjs.org/package/jsbn},
 * [jsHashes]{@link https://github.com/h2non/jsHashes} and
 * [ws]{@link https://www.npmjs.org/package/ws}.
 * @module SRPServerPrototype
 * @author Martin Springwald
 * @license MIT
 * @requires BigInteger
 * @requires crypto
 * @requires Hashes
 * @requires SRP
 * @requires ws
 */
 
// Required modules
/** jsbn */ BigInteger = require('./lib/jsbn.js');
/** jsHashes */ Hashes = require('../shared/lib/hashes.min.js');
/** @type {SRP} */ SRP = require('../shared/lib/srp.js');
/** ws */ WebSocket = require('ws');

/*jshint supernew:true */

/**
 * User Manager (singleton)
 * @constructor
 */
User = new function() {
	/** @member {Array} module:SRPServerPrototype~User#users
		@desc user list (may be stored in database)
	*/
	this.users = [
		{
			name: "root",
			salt: "salt",
			verifier: "17281681339250659452869715096364624846955219644440606375367447322932643610573774037629577111612424169159303574569307696436551418666878689316817660768489464350611262323340975364998273912013181104191965887408400154962599755510847161170062664813403881303989919988345166332369472849137013085164027585608893076708732729828140345482849044653635759320490889091933723878456366031982298039721313561216004927597645172185991788407089641288019344147164805119088053636791823113647560584737369044980529845512348489238201031331415915255916931096139902433534923805492836022877498329552958719476867075550071293688935897895433246988333"
		}
	];
	/** return user object by name
		@param {string} name (name)
		@param {function} callback (function(user) {})
	*/
	this.getUserByName = function(name, callback) {
		// iterate over user list (may be replaced by database lookup)
		var i; for (i = 0; i < this.users.length; i++) {
			if (this.users[i].name == name) {
				callback(this.users[i]);
			}
		}
	};

}();

/**
 * WebSocketServer (singleton)
 * @constructor
 */
WebSocketServer = new function() {
	/** @member {Array} module:SRPServerPrototype~WebSocketServer#activeSockets
		@desc list of active sockets
	*/
	this.activeSockets = [];
	/** handle authentication (SRP)
		@param {WebSocket} ws (web socket)
		@param {object} jsonMsg (JSON)
	*/
	this.handleAuth = function(ws, jsonMsg) { 
		// reset authorization state
		if (!ws.session) ws.session = {};
		ws.session.auth = false;
		// initialize SRP
		if (!ws.srp) {
			ws.srp = new SRP();
			ws.srp.init();
		}
		// case 1: received I (user name) and A (client random value)
		if (jsonMsg.payload.I&&jsonMsg.payload.A) {
			ws.srp.I = jsonMsg.payload.I;
			ws.srp.A = new BigInteger(jsonMsg.payload.A, 10);
			if (!ws.srp.verifyA()) {
				// verification of A failed: exit
				return;
			}
			// lookup user by name (I) and compute B (server random value)
			User.getUserByName(jsonMsg.payload.I, function(user) {
				// attach user to session and compute B
				ws.session.user = user;
				ws.srp.v = new BigInteger(user.verifier, 10);
				ws.srp.s = user.salt;
				ws.srp.computeB();
				// send salt and B
				WebSocketServer.send(ws, {
					"response": "auth", 
					"payload": {
						s: ws.srp.s,
						B: ws.srp.B.toString()
					}
				});
			});
		}
		// case 2: received M1
		if (jsonMsg.payload.M1) {
			// compute K and M1
			ws.srp.computeServerK();
			ws.srp.computeM1();
			if (ws.srp.M1 !== jsonMsg.payload.M1) {
				// verification of M1 failed: exit
				return;
			}
			// authorized
			ws.session.auth = true;
			// compute and send M2
			WebSocketServer.send(ws, {
				"response": "auth", 
				"payload": {
					M2: ws.srp.computeM2().toString()
				}
			});
		}
	};
	/** handler for socket close
		@param {WebSocket} ws (web socket)
		@param {object} err (error object)
	*/
	this.onClose = function(ws, err) {
		// iterate over socket list and remove closed socket from list
		var i; for (i = 0; i < this.activeSockets.length; i++) {
			if (this.activeSockets[i] === ws) { this.activeSockets.splice(i, 1); break; }
		}
	};
	/** handler for socket accept
		@param {WebSocket} ws (web socket)
	*/
    this.onConnection = function(ws) {
		// add new socket to socket list
		this.activeSockets.push(ws);
		// register onMessage and onClose handlers
        ws.addListener("message", function(r) { WebSocketServer.onMessage(ws, r); });
        ws.addListener("close", function(r) { WebSocketServer.onClose(ws, r); });
    };
	/** handler for socket data
		@param {WebSocket} ws (web socket)
		@param {string} message (data)
	*/
    this.onMessage = function(ws, message) {
        try {
			// parse message string as JSON object
			var jsonMsg = JSON.parse(message);
			// choose action handler by specified action in message object
			/*jshint onecase:true */
			switch (jsonMsg.action) {
				case "auth": this.handleAuth(ws, jsonMsg); break;
			}
		} catch(e) { return; }
    };
	/** send data (JSON object as string) over socket
		@param {WebSocket} ws (web socket)
		@param {object} jsonMsg (JSON)
	*/
    this.send = function(ws, jsonMsg) {
		ws.send(JSON.stringify(jsonMsg));
	};
    
}();

/**
 * Setup WebSocket Server
 */
(new WebSocket.Server({
	host: "127.0.0.1",
	port: 8080
})).addListener('connection', function(ws) {
	WebSocketServer.onConnection(ws);
});
