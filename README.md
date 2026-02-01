SCHAT:

1. Overview
2. Installation
3. Usage
4. Configuration
5. License

1) OVERVIEW:

This project implements a secure client–server architecture that enables encrypted communication between clients.
A central server is used solely for coordination and message routing, 
while all sensitive communication remains end-to-end encrypted.

Clients first establish a secure and authenticated communication channel with the server. 
Using this channel, two clients can negotiate an end-to-end encrypted (E2EE) session using the X3DH (Extended Triple Diffie-Hellman) 
key agreement protocol, providing mutual authentication and resistance to man-in-the-middle (MITM) and replay attacks. 
Once a shared secret is established, a Single Ratchet mechanism is used to derive per-message keys, 
ensuring forward secrecy for ongoing communication.

The server has no access to plaintext messages or cryptographic session keys
and is unable to decrypt, read, or modify client-to-client communications.


The system provides the following security properties:

-End-to-End Encryption (E2EE):
Only the communicating clients can read message contents. The server acts as a blind relay.

-Authentication:
Clients authenticate each other during session establishment via X3DH, preventing impersonation and MITM attacks.

-Forward Secrecy:
Compromise of long-term or current session keys does not expose past messages due to the use of a Single Ratchet.

-Message Integrity:
Messages are cryptographically authenticated, ensuring that any tampering or modification in transit is detected.

-Confidentiality:
Message contents remain private even if the server is compromised.

-Resistance to Replay Attacks
The ratcheting mechanism ensures that message keys are used only once.

The cryptographic design of this project is inspired by the Signal Protocol, specifically:
X3DH for asynchronous authenticated key agreement
Single Ratchet for forward-secure message encryption
!!it does not include a Double Ratchet!!

Out of Scope:
Physical compromise of client devices. Although the db is locally encrypted
Side-channel attacks (timing, power analysis)
Denial-of-Service (DoS) attacks
Traffic analysis and metadata protection


2) INSTALLATION:

Run "client_setup.rb" for a new client database or "server_setup.rb" for a new server database.
During the setup minimal user input is required


3) USAGE:
Server: The server will print it's fingerprint (the signing public key) when switching it on.
  After that the user will be asked to print vouchers.
  It'll be required for clients to know both the fingerprint and have a valid voucher in order to communicate with the server.
  No voucher: no access to the server functionalities
  !!!! The number of concurrent threads is fixed to 20 There is no DDOS protection !!!!

Client: First it'll be requested to give a valide server fingerprint, with format (ab11:f43d:9983...:bb32).
  Register with the server, a valid voucher is required.
  Share with the server the e2ee keys, in order for others to communicate with you.
  At this point you can either request to communicate with a given user or obtain messages stored on the server from other users.
  Once the messages are obtained ask to print them on screen


4) CONFIGURATION:
The databases are in the schat_db folder, no configuration is actually required 
!!!!!!
Make sure to have ruby's sqlite3 gem installed with sqlcipher:
gem install sqlite3 -- --with-sqlcipher
if sqlite3 gem is already installed remove it first and then reinstall with sqlcipher
otherwise your messages will be saved in plain text on the db.
!!!!!!

5) LICENSE: MIT
