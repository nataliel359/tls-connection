# EECS3482: Introduction to Computer Security

## Assignment 2: TLS

You're presented with a simple client/sever  application.


### Files

- **server.py**: Server application.
- **client.py**: Client application.
- **lib/**: Contains helper functions for communication.
- **data/**: Contains cryptographic keys.
  - `rootCA.pem`: Root certificate (password: `eecs3482`)
  - `server.key`: Server private key.
  - `server.pem`: Server certificate (password: `eecs3482server`)
  - `client_priv_key.pem`: Client private key.
  - `client_pub_key.pem`: Client public key.
	 

### Set-up

To install all the relevant packages run:

* make clean
* make




## Instructions 

### Server app
To run a server in a  terminal run 
	* make server
	or (without make)
	*  python3 server.py –p [port #]

### Client app
*  client.py is client app 
    *  To run a client: make client
    *   or python3 client.py –p [port #]













