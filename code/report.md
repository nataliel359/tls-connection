---
title: EECS 3482 Report
author: Natalie Lewis
...


#### Question 1

If the client were to respond with a hash of the challenge, r = SHA-256(l), and the server were to verify that r = SHA-256(l) instead, this would remove the authenticity verification portion of the protocol. In turn, this makes the protocol susceptible to a replay attack. If the adversary were to intercept the challenge l, they could impersonate the client by resending a hashed response and the server would verify the response without knowing that the client's identity has been compromised.


#### Question 2

In terms of the loading and storing of the client keys, there are no protocols in place to ensure confidentiality or integrity. An attack that an adversary can perform to obtain the client's keys is a chosen plaintext attack. If the adversary gains access to the files, they can easily read the plaintext and obtain the client's keys for impersonation. An improvement to combat this issue is to encrypt the data on the disk to ensure confidentiality and integrity. This can be done by a simple password scheme unique to the client or a shared secret between the client and the user. Another problem is that there are no specific file permissions needed to access the key files, therefore, anyone can access them on the disk. An improvement to avoid this issue is to implement file permissions on the key files so that an adversary cannot easily access and read the files.


#### Question 3

One advantage of using symmetric-key challenge-response is that this has reduced latency so it is generally faster to perform this protocol as opposed to the public-key protocol Storing a symmetric key and verifying a hashed response takes much less time to compute than verifying a signature and the validity of a certificate. One disadvantage of using MAC-based challenge-response instead of signature-based challenge-response is that key management becomes more difficult when dealing with multiple clients and servers. If a client wants to connect to multiple servers, they need a symmetric key for each server and vice versa. This is much harder on storage, limiting the amount of concurrent connections possible.


#### Question 4

A password authentication scheme would work by having the server prompt the user for the correct password and the client would send the password to the server. The password would be verified by the server and then successfully establish the TLS connection. Instead of storing the client's public key, the server would store an HMAC with the password and the salt to ensure the integrity and authenticity of the password. This info should not just be the client's password because this scheme is already less secure than the signature-based challenge-response. Password vulnerabilities include reused passwords, poor passwords and multiple password use. This is why the salt is integrated with the password and the hash function is applied to ensure security and prevent attacks where an adversary could obtain the password.