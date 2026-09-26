# TLS Security & Protocol Analysis Lab

## Overview

This project investigates TLS-secured client/server communication
using Python and Wireshark. The project analyzes the TLS handshake,
X.509 certificate validation, megotiated TLS version and cipher suite,
and encrypted application traffic.

The lab also demonstrates how TLS protects application data from passive network observation while allowing the client to authenticate the server using X.509 certificates.

## Technologies

- Python
- Python ssl lirary
- Wireshark
- OpenSSL
- TLS
- X.509 certificates

## Architecture

Client -> Client Hello -> Server
Client <- Server Hello <- Server
Client <- Certificate / authenicated handshake <- Server
Client <-> Encrypted application data <-> Server

> Note: The server certificate was not directly visible in the Wireshark capture used for this lab. Therefore, certificate properties were not extracted from the packet capture.

## TLS Handshake Analysis

The client initiates the TLS connection with a Client Hello containing supported TLS versions and cipher suites.

The server responds with a Serer Hello and establishes the 
parameters used for the connection.

The TLS handshake uses server authentication through an X.509 certificate configured for the TLS server. The Python ssl library handles certificate vertification according to the client's TLS configuration and trusted certificate authorities.

After the handshake is completed, application data is transmitted 
through the encrypted TLS connection.

## Wireshark Evidence

![TLS Handshake](tls_handshake.png)

![Encrypted Application Data](encrypted_application_data.png)

The Wireshark capture demonstrates the TLS handshake and encrypted application traffic.

The captured traffic did not provide directly inspectable server certificate properties. Since these details were not available, this project does not claim packet-level extraction of the server certificate.

## Certificate Analysis

The TLS server uses an X.509 certificate for server authentication.

Certificate validation is performed through the Python ssl configuration and its configured certificate authority/trust settings.

The following certificate properties were not directly extracted or printed during this lab:

- Subject
- Issuer
- Validity period
- Public Key Algorithm
- Signature Algorithm
- Subject Alternative Name

Connsequently, these properties are not presented as experimentaln results in this report.

The original project also contained an expired certificate. This demonstrated the importance of certifiacte validity periods and certificate lifecycle management. The certifiacte was regenerated for the updated lab.

## TLS Version & Cipher Suite

The connection negotiated:

- TLS Version: 1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
- Key Length: 32

The negotiated TLS parameters were obtained from th Python TLS connection.

TLS 1.3 provides a modern cryptographic baseline and encrypts sensitive portions of the handshake, including certificate-related handshake messages, after the initial negotiation.

## Security Findings

### Confidentiality

Application data is encrypted after the TLS handshake, preventing
a passive network observer from reading the transmitted plaintext.

This was documented in Wireshark, where application traffic appeared as encrypted TLS Application Data rather than the original plaintext.

### Authentication

The TLS connection uses X.509 certificates to provide server authentication. The Python ssl library performs certificate verification according to the client's configured trust settings.

The Wireshark capture did not expose the server certificate properties, so certificate validation cannot be independently demonstrated through the packet capture alone.

### Integrity

TLS provides authenticated encryption for application traffic, allowing tampering with encrypted application data to be detected.

### Certificate Lifecycle

The original project contained an expired certificate. This
demonstrated the importance of certificate validity periods and 
certificate lifecycle management. 
The certificate was regenerated for the updated lab, allowing the TLS connection to establish successfully with the updated certificate configuration.

## Key Takeaways

This investigation demonstrated how TLS establishes an authenticated
and encrypted communication channel and how Wireshark can be used
to analyze TLS protocol behaviour and encrypted application traffic.

The lab also demonstrated an important limitation of network-level TLS analysis: not every certificate property is necessarily visible in a packet capture. In TLS 1.3, portions of the handshake are encrypted, making direct inspection of certificate information in Wireshark dependent on the available capture and TLS decryption configuration.

The Python ssl library provided the client-side TLS imlementation and certificate validation, while Wiresharl provided visibility into the network TLS handshake and encrypted traffic.

## How to Run

1. Change directory to code folder
2. Install the required Python dependencies
3. Start the TLS server
4. Start the TLS client
5. Capture the connection using Wireshark
6. Filter traffic using `tls`
7. Examine the TLS handshake and encrypted Application Data packets

## Project Structure

```text
client.py
server.py
captures/
screenshots/
README.md
```