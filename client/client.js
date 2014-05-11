/**
 * Client with SRP authentication on HTML5 JavaScript. Requires
 * [WebSocketAPI]{@link http://www.w3.org/TR/websockets}.
 * @module SRPClientPrototype
 * @author Martin Springwald
 * @license MIT
 * @requires SRP
 * @requires WebSocket
 */
 
/**
 * DOM shortcut
 * @param {string} x (ID)
 * @returns {DOMElement}
 */
var $ = function(x) { return document.getElementById(x); };

/*jshint supernew:true */

/**
 * Login (singleton)
 * @constructor
 */
var Login = new function() {
	/** @member {SRP} module:SRPClientPrototype~Login#srp */
	this.srp = null;
	/** begin authentication procedure */
	this.begin = function() {
		// initalize SRP
		this.srp = new SRP();
		this.srp.init();
		// compute A
		this.srp.computeA();
		this.srp.I = $("user").value;
		// send A and I
		WebSocketClient.send({
			action : "auth",
			payload: {
				I: Login.srp.I,
				A: Login.srp.A.toString()
			}
		});
	};
	/** print message
		@param {string} message (message to print)
	*/
	this.message = function(message) {
		$("messages").innerHTML = message;
	};
	/** handler to receive data
		@param {object} data (JSON)
	*/
	this.receive = function(data) {
		if (data.payload) {
			// case 1: received s and B
			if (data.payload.s&&data.payload.B) {
				this.srp.s = data.payload.s;
				this.srp.B = new BigInteger(data.payload.B, 10);
				if (!this.srp.verifyB()||!this.srp.verifyHAB()) {
					this.message("Connection could not be secured!");
					return;
				}
				this.srp.p = $("pass").value;
				this.srp.computeVerifier();
				this.srp.computeClientK();
				WebSocketClient.send({
					action : "auth",
					payload: {
						M1: this.srp.computeM1()
					}
				});
			}
			// case 2: received M2
			if (data.payload.M2) {
				this.srp.computeM2();
				if (this.srp.M2 !== data.payload.M2) {
					this.message("Connection could not be secured!");
					return;
				}
				// success
				this.message("Authentication successful!");
			}
		}
	};
}();

/**
 * WebSocket Client (singleton)
 * @constructor
 */
var WebSocketClient = new function() {
	/** @member {WebSocket} module:SRPClientPrototype~WebSocketClient#websocket */
	this.websocket = {};
	/** initialize websocket and connect to server*/
	this.init = function() {
		// connect to server
		this.websocket = new WebSocket("ws://127.0.0.1:8080/ws");
		// register event handler
		this.websocket.addEventListener("message", this.onMessage, false);
	};
	/** onMessage handler
		@param {DOMEvent} event (WebSocket Event)
	*/
	this.onMessage = function(event) {
		try {
			var jsonData = JSON.parse(event.data);
			/*jshint onecase:true */
			switch (jsonData.response) {
				case "auth": Login.receive(jsonData); break;
			}
		} catch(e) { return; }
	};
	/** send (JSON message as string)
		@param {object} jsonData (JSON)
	*/
	this.send = function(jsonData) {
		this.websocket.send(JSON.stringify(jsonData));
	};
}();

/**
 * Init
 */
window.addEventListener('load', function() {
	WebSocketClient.init();
	$("login").addEventListener("click", function() {
		Login.begin();
	}, false);
}, false);
