'''
    *  Full Name: Natalie Lewis
    *  Course: EECS 3482 A
    *  Description: Client program. Established connection with the server.
    *  FOR EDUCATION PURPOSES OF ONLY. DO NOT DITSRIBUTE.
'''
import socket
import sys
import os
import getopt
import pickle
import datetime

import ssl
import logging

from lib.comms import Conn
from lib.comms import Message

from Crypto.PublicKey import ECC

# Import Digital Signature Standard Algorithm to ensure authentication of the client's identity
from Crypto.Signature import DSS

# Import SHA256 Hash to encode the challenge and send the response to the client
from Crypto.Hash import SHA256


class Client:

    def __init__(self,
                 client_key_password,
                 ca_crt_path,
                 port):
        """
            client_key_password: The password used to protect the client’s private key.
            ca_crt_path: The path to the certificate for the certificate authority (CA).
            port: An integer representing the TCP port on which the client connects to the server.
        """

        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M',
                            filename='client.log',
                            filemode='w')
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(name)-12s: %(levelname)-8s %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

        self.client_log = logging.getLogger(self.__class__.__name__)

        # use and do not change internal variables names

        self._port = port
        self.client_key_password = None
        self.client_priv_key = None
        # Resolve the trusted lab CA relative to this script.
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        self.ca_crt_path = ca_crt_path or os.path.join(data_dir, "lab_rootCA.pem")

        self.protocol_state = 'START'
        self.sconn = None

        # This dictionary contains the CA certificate, the name of the host and the port
        self.client_ssl_options = {
            # TODO: Fill in options
            "ca_certificate": self.ca_crt_path,
            "host": "localhost",
            "port": self._port
        }

        self.generate_client_keys()

    def generate_client_keys(self):

        key = ECC.generate(curve='P-256')
        # Keep client key files independent of the caller's working directory.
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        private_key_path = os.path.join(data_dir, "client_priv_key.pem")
        public_key_path = os.path.join(data_dir, "client_pub_key.pem")

        if not os.path.exists(private_key_path):
            f = open(private_key_path, 'wt')
            f.write(key.export_key(format='PEM')) # Unencrypted private key (either encrypt it or id this as a weakness in the README)
            f.close()

        if not os.path.exists(public_key_path):
            f = open(public_key_path, 'wt')
            f.write(key.public_key().export_key(format='PEM'))
            f.close()

        self.client_priv_key = ECC.import_key(
            open(private_key_path).read())

    def protocol_abort(self):
        """
         Return: nothing

         This function should generate a challenge (encoded as a string) to send to the client.
        """
        self.client_log.info('Abort protocol intiated')
        self.protocol_state = 'ABORT'
        exit(0)

    def check_cert(self, cert):
        """
        Return Boolean: True the cetificate is valid
        """
        # TODO: implement the X.509 certificate checks

        # Checks if the certificate contains the following fields, otherwise it is invalid
        if not ('notBefore' in cert and 'notAfter' in cert and 'issuer' in cert and 'subject' in cert):
            return False

        # Convert certificate validity bounds to UTC timestamps for comparison.
        not_before = ssl.cert_time_to_seconds(cert['notBefore'])
        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()

        # Check if the certificate is within the validity period, otherwise it is invalid
        if not (not_before <= now <= not_after):
            return False

        # Checks if the certificate is going to expire within the next 7 days, otherwise it is valid
        if (not_after - now) < 7 * 24 * 60 * 60:
            return False
        
        # Checks if the following fields match to the correct values
        correct_values = {
            "countryName": "CA",
            "stateOrProvinceName": "ON",
            "localityName": "York",
            "organizationName": "EECS 3482",
            "organizationalUnitName": "Assignment 2",
            "commonName": "localhost",
            "emailAddress": "eecs3482@yorku.ca"
        }
        subject_dict = {
            key: value 
            for rdn in cert.get("subject", ()) 
            for key, value in rdn
        }

        for correct_key, correct_value in correct_values.items():
            actual_value = subject_dict.get(correct_key)
            if actual_value != correct_value:
                return False

        return True

    # Prompt for one message and send it through the authenticated connection.
    def send_session_message(self, sconn):
        message = input("You (/quit to exit): ")
        msg = pickle.dumps({
            "type": Message.SESSION_MESSAGE,
            "msg": message.encode("utf-8")
        })
        sconn.send(msg)

    def process_server_msg(self, sconn):
        """
        sconn: socket wrapper between client and server

        Return: nothing
        """

        while True:
            data = sconn.recv()
            recv_msg = pickle.loads(data)
            
            if recv_msg['type'] == Message.CHALLENGE:
                self.client_log.info('Challenge received')

                # TODO: Respond to challenge
                
                hash_challenge = SHA256.new(recv_msg['msg'].encode()) # Creates a SHA-256 hash of the challenge generated by the server
                signer = DSS.new(self.client_priv_key, 'fips-186-3') # Creates a signer object to sign the challenge messageS
                signature = signer.sign(hash_challenge) # Signs the challenge message

                self.client_log.info('Sending response')
                msg = pickle.dumps(
                    {"type": Message.RESPONSE, 'msg': signature})
                sconn.send(msg)

            # Begin client-initiated messaging only after challenge verification.
            elif recv_msg['type'] == Message.SUCCESS:
                self.send_session_message(sconn)

            elif recv_msg['type'] == Message.SESSION_MESSAGE:
                # Finish on the echoed quit command; otherwise prompt for another message.
                message = recv_msg['msg'].decode("utf-8")
                self.client_log.info("Pong msg [%s]" % message)
                if message == "/quit":
                    self.protocol_state = 'END'
                    return
                self.send_session_message(sconn)

    def connect(self):
        """
        Establishes connections between client and client on self._port.

        Return: nothing
        """

        try:
            print(self.client_ssl_options['ca_certificate'])
            if self.client_ssl_options['ca_certificate']:
                self.client_log.info("Initiating a TLS connection [port %d]" % self._port)

                # Create a socket and wrap it with SSL context
                # Require a trusted certificate and verify the requested host name.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(self.client_ssl_options['ca_certificate'])

                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                secure_socket = context.wrap_socket(conn, server_hostname=self.client_ssl_options['host'])
                print("TLS Version:", secure_socket.version())
                print("TLS Cipher:", secure_socket.cipher())
                secure_socket.connect((self.client_ssl_options['host'], self.client_ssl_options['port']))

                # FIND OUT WHAT TLS STACK VALIDATES AUTOMATICALLY AND WHAT HAPPENES WHEN THE CERT FAILS
                
                # Get the peer's certificate
                peer_certificate = secure_socket.getpeercert()

                # Check if the certificate is valid        
                if not self.check_cert(peer_certificate):
                    self.client_log.error('invalid certificate received')
                    self.protocol_abort()
            else:
                # without proper TLS setup we are on unsecure channel
                self.client_log.warning("Initiated Insecure Communication")
                secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                secure_socket.connect(("localhost", self._port))

            self.client_log.info('Connected to server')
            self.sconn = Conn(secure_socket, client=True)
            self.process_server_msg(self.sconn)

        except socket.error as se:
            self.client_log.error("Connection error on port %d [%s]", self._port, se)


def main(argv):

    # default port
    server_port = 1337
    try:
        opts, args = getopt.getopt(argv, "hp:", ["port="])
    except getopt.GetoptError:
        print('client.py -port <port>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('client.py -port <port>')
            sys.exit()
        elif opt in ("-p", "--port"):
            if arg:
                server_port = int(arg)

    # Load the lab CA by a path that works regardless of the current directory.
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    Client(None,
           os.path.join(data_dir, "lab_rootCA.pem"),
           server_port).connect()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("\nDone!")
