The Secure Remote Password Protocol lets you authenticate password secured
logins without having to transmit the plain text password by establishing a
cryptographic key (Password-Authenticated Key-Agreement = PAKE).

SRP is a standard defined in [RFC 2945](http://tools.ietf.org/html/rfc2945)
and originally developed by [Tom Wu](http://www-cs-students.stanford.edu/~tjw),
who also developed the BigInteger library used by this project. This software
implements version 6 of the SRP protocol using HTML5/JavaScript technology on
client and server side.

Client requires a HTML5 capable web browser. WebSockets are utilized to
exchange messages in order to establish a cryptographic key. Node.js is
required on server side with WebSocket module installed (npm -g install ws).
Static pages may be delivered via standard http server (e.g. Apache or Nginx).

Run prototype implementation:
* Server: node server.js
* Client: open "index.html", enter "root" and "1234" as user/pass and submit
* Shortly after, a message showing "Authentication successful!" should appear

The actual SRP implementation is located in shared/lib/srp.js whereas
client/client.js and server/server.js orchestrate the communication flow over
WebSockets and the SRP steps.

Feel free to adjust parameters or client/server logic to your needs, since this
is only a prototype implementation. You may also exchange cryptographic hashing
algorithm and key derivation function by algorithms of your choice. Currently
SHA256 is used for cryptographic hashing and scrypt with N=16384, r=8, p=1 and
L=64 is used for iterative key derivation. For productive use you may also
generate your own large safe prime as modulus (N) for arithmetic operations.
However, the provided N (AC6B...FF73) will work out of the box. It is taken
from [RFC5054 Appendix A (SRP Group Parameters)](http://tools.ietf.org/html/
rfc5054#appendix-A) and a proven safe prime of 2048 bit length with a generator
(g) of 2. Please note, that you will have to reset all user passwords if you
modify hash or key derivation algorithms or the modulus.

The current implementation of the software is not specifically optimized for
performance or load balancing, which may result in weakness for denial of
service attacks in the worst case.

Another problem which may arise under heavy load is to provide enough entropy
for the cryptographic strong random number generators to work. If not enough
entropy is available then an exception will be thrown and the authentication
process will immediately abort. You may modify the computeRandom function to
supply more entropy sources if needed or to not abort and instead wait until
enough entropy is available.

Although because of the nature of the protocol it is not necessary to secure
the connection with SSL/TLS during key exchange, it is recommended to always
use WebSocketSecure to prevent firewall issues with plain WebSocket traffic.

This software is free and open source. See LICENSE for details.
