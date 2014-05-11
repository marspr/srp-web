/**
 * @module SRP
 * @author Martin Springwald
 * @license MIT
 * @description Secure Remote Password Protocol (RFC 2945) Version 6 JavaScript Implementation. Requires
 * [node.js/api/crypto]{@link http://nodejs.org/api/crypto.html},
 * [jsbn]{@link http://www-cs-students.stanford.edu/~tjw/jsbn/},
 * [jsHashes]{@link https://github.com/h2non/jsHashes},
 * [js-scrypt]{@link https://github.com/tonyg/js-scrypt} and
 * [WebCryptoAPI]{@link http://www.w3.org/TR/WebCryptoAPI}.
 * @requires BigInteger
 * @requires Hashes
 * @requires scrypt_module_factory
 * @requires crypto
 * @requires window.crypto
 */
if (typeof module !== 'undefined') {
	module.exports = SRP;
}

/**
 * @class SRP
 * @constructor
 * @description Secure Remote Password Protocol (RFC 2945) Version 6 JavaScript Implementation
 */
function SRP() {
	/** @member {BigInteger} SRP#N
		@desc large safe prime */ this.N = null;
	/** @member {BigInteger} SRP#g 
		@desc generator */ this.g = null;
	/** @member {BigInteger} SRP#a
		@desc client random */ this.a = null;
	/** @member {BigInteger} SRP#b
		@desc server random */ this.b = null;
	/** @member {BigInteger} SRP#A
		@desc g^a */ this.A = null;
	/** @member {BigInteger} SRP#B
		@desc g^b + kv */ this.B = null;
	/** @member {string} SRP#clientK
		@desc session key */ this.clientK = null;
	/** @member {string} SRP#serverK
		@desc session key */ this.serverK = null;
	/** @member {string} SRP#M1
		@desc proof client session key */ this.M1 = null;
	/** @member {string} SRP#M2
		@desc proof server session key */ this.M2 = null;
	/** @member {BigInteger} SRP#k
		@desc asymmetry factor */ this.k = null;
	/** @member {string} SRP#I
		@desc username */ this.I = null;
	/** @member {string} SRP#p
		@desc password */ this.p = null;
	/** @member {BigInteger} SRP#x
		@desc password hash */ this.x = null;
	/** @member {string} SRP#s
		@desc salt */ this.s = null;
	/** @member {BigInteger} SRP#v
		@desc verifier */ this.v = null;
}

/**
 * Initialize with default N and g. May be overwritten with own N and g, where
 * N must be a large safe prime and g an appropriate generator.
 */
SRP.prototype.init = function() {
	this.N = new BigInteger("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16);
	this.g = new BigInteger("2");
};
 
/**
 * Run a full test with example password and salt. Client K and Server K will
 * match if successful. Results will be printed to console.
 */
SRP.prototype.test = function() {
	this.init();
	this.I = "root";
	this.p = "1234";
	this.s = "salt";
	this.computeVerifier();
	this.computeA();
	var vA = this.verifyA();
	console.log("Verify A", vA);
	this.computeB();
	var vB = this.verifyB();
	console.log("Verify B", vB);
	var vHAB = this.verifyHAB();
	console.log("Verify H(A,B)", vHAB);
	var cK = this.computeClientK();
	var sK = this.computeServerK();
	var M1 = this.computeM1();
	var M2 = this.computeM2();
	console.log("Client K", cK);
	console.log("Server K", sK);
	var vK = this.verifyK();
	console.log("Verify K", vK);
	console.log("M1", M1);
	console.log("M2", M2);
};

/**
 * compute password hash, may be overriden if needed
 *
 * @param {string} s (salt)
 * @param {string} p (password)
 * @returns {string} hash
 */
SRP.prototype.computePasswordHash = function(s, p) {
	// load hash factory into memory, if not initialized already
	if (!this.scrypt) this.scrypt = scrypt_module_factory();
	// use scrypt with N=16384, r=8, p=1, L=64
	return this.scrypt.to_hex(this.scrypt.crypto_scrypt(this.scrypt.encode_utf8(p), this.scrypt.encode_utf8(s), 16384, 8, 1, 64));
};

/**
 * compute hash, may be overridden if needed
 *
 * @param {string} s (string to hash)
 * @returns {string} hash
 */
SRP.prototype.computeHash = function(s) {
	if (typeof module === 'undefined') {
		// use jsHashes library
		// load hash factory into memory, if not initialized already
		/*jshint supernew:true */
		if (!this.SHA256) this.SHA256 = new Hashes.SHA256();
		// use SHA256
		return this.SHA256.hex(s);
	}
	else {
		var hash = new Hashes.SHA256;
		return hash.hex(s);
	}
};

/**
 * compute random, may be overridden if needed
 * @todo add more entropy
 *
 * @throws Will throw an error if not enough entropy is available.
 * @returns {BigInteger} random
 */
SRP.prototype.computeRandom = function() {
	var rndBuf;
	var rnd;
	try {
		if (typeof module == "undefined") {
			if (window.crypto.getRandomValues) {
				// prepare byte array with L=32
				rndBuf = new Uint8Array(32);
				// use browser crypto engine
				// @TODO add more entropy
				window.crypto.getRandomValues(rndBuf);
				// convert byte array into BigInteger
				rnd = new BigInteger(rndBuf, 256);
				rnd = rnd.abs();
				return rnd;
			}
		}
		else {
			var crypto = require('crypto');
			// use node crypto engine
			// @TODO add more entropy
			rndBuf = crypto.randomBytes(32);
			// convert byte array into BigInteger
			rnd = new BigInteger(rndBuf, 256);
			rnd = rnd.abs();
			return rnd;
		}
	} catch(e) {
		throw "Not enough entropy";
	}
};

/**
 * compute verifier, requires p and s
 *
 * @returns {BigInteger} verifier
 */
SRP.prototype.computeVerifier = function() {
	// set password
	this.x = new BigInteger(this.computePasswordHash(this.s + "" + this.p), 16);
	// set verifier
	this.v = this.g.modPow(this.x, this.N); // g^x
	return this.v;
};

/**
 * compute A
 *
 * @returns {BigInteger} A
 */
SRP.prototype.computeA = function() {
	// set asymmetry factor
	this.k = new BigInteger(this.computeHash(this.N.toString() + "" + this.g.toString()), 16);
	// compute random until it fits requirements by specification
	do {
		// set client random
		this.a = this.computeRandom();
		// set g^a
		this.A = this.g.modPow(this.a, this.N); // g^a
	} while (this.A.mod(this.N).equals(BigInteger.ZERO));
	return this.A;
};

/**
 * compute B
 *
 * @returns {BigInteger} B
 */
SRP.prototype.computeB = function() {
	// set asymmetry factor
	this.k = new BigInteger(this.computeHash(this.N.toString() + "" + this.g.toString()), 16);
	// set server random
	this.b = this.computeRandom();
	var Bl = this.k.multiply(this.v); // k*v
	var Br = this.g.modPow(this.b, this.N); // g^b
	var Bn = Bl.add(Br); // k*v + g^b
	// set B
	this.B = Bn.mod(this.N); // (k*v + g^b) % N
	return this.B;
};

/**
 * compute M1, requires A, B, I, K and s
 *
 * @returns {string} M1
 */
SRP.prototype.computeM1 = function() {
	var HN = new BigInteger(this.computeHash(this.N.toString()), 16);
	var Hg = new BigInteger(this.computeHash(this.g.toString()), 16);
	var HI = new BigInteger(this.computeHash(this.I.toString()), 16);
	// set M1
	this.M1 = this.computeHash(HN.xor(Hg).toString() + "" + HI.toString() + "" + this.s + "" + this.A.toString() + "" + this.B.toString() + "" + (this.clientK?this.clientK:this.serverK)); // H(H(N) XOR H(g), H(I), s, A, B, clientK)
	return this.M1;
};

/**
 * compute M2, requires A, K and M1
 *
 * @returns {string} M2
 */
SRP.prototype.computeM2 = function() {
	// set M2
	this.M2 = this.computeHash(this.A.toString() + "" + this.M1 + "" + (this.serverK?this.serverK:this.clientK));
	return this.M2;
};

/**
 * compute client K, requires A and B
 *
 * @returns {string} K
 */
SRP.prototype.computeClientK = function() {
	var u = new BigInteger(this.computeHash(this.A.toString() + "" + this.B.toString()), 16);
	var Sl = this.B.add(this.k.multiply(this.g.modPow(this.x, this.N)).negate()); // B - k*g^x
	var Sr = this.a.add(u.multiply(this.x)); // a + u*x
	var S = Sl.modPow(Sr, this.N); // (B - k*g^x) ^ (a + u*x)
	// set client K
	this.clientK = this.computeHash(S.toString());
	return this.clientK;
};

/**
 * compute server K, requires A and B
 *
 * @returns {string} K
 */
SRP.prototype.computeServerK = function() {
	var u = new BigInteger(this.computeHash(this.A.toString() + "" + this.B.toString()), 16);
	var Sl = this.A.multiply(this.v.modPow(u, this.N)); // A*v^u
	var S = Sl.modPow(this.b, this.N); // (A*v^u)^b
	// set server K
	this.serverK = this.computeHash(S.toString());
	return this.serverK;
};

/**
 * verify A
 *
 * @returns {boolean} result
 */
SRP.prototype.verifyA = function() {
	if (!this.A.equals(BigInteger.ZERO)) {
		if (!this.A.mod(this.N).equals(BigInteger.ZERO)) {
			return true;
		}
	}
	return false;
};

/**
 * verify B
 *
 * @returns {boolean} result
 */
SRP.prototype.verifyB = function() {
	if (!this.B.equals(BigInteger.ZERO)) {
		if (!this.B.mod(this.N).equals(BigInteger.ZERO)) {
			return true;
		}
	}
	return false;
};

/**
 * verify HAB
 *
 * @returns {boolean} result
 */
SRP.prototype.verifyHAB = function() {
	var u = new BigInteger(this.computeHash(this.A.toString() + "" + this.B.toString()), 16);
	if (!u.equals(BigInteger.ZERO)) {
		return true;
	}
	return false;
};

/**
 * verify K, returns true if client K and server K match
 *
 * @returns {boolean} result
 */
SRP.prototype.verifyK = function() {
	if (this.clientK && this.serverK) {
		if (this.clientK === this.serverK) {
			return true;
		}
	}
	return false;
};
