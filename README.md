
This project is an implementation of a secure web service according to the Open Standards Everywhere (OSE)[1] guidelines by the Internet Society. As an overview, the necessary theory will be presented, covering encryption, public and private keys, hashing, SSL/TLS, DNSSEC, HTTP/2, and IPv6. Following that, the practical aspect will be demonstrated: a website hosted on an Apache HTTP server within a Virtual Machine (VM) instance in the Google Cloud Platform (GCP), implemented according to the OSE guidelines, along with a TLS handshake analysis in Wireshark.

# Theory

### Encryption and Hashing

With cryptography, there are a few ways to ensure confidentiality.

One method is **symmetric encryption**, which uses a single key to both encrypt and decrypt a message.

<img width="416" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/34888475-4bd3-4e78-8631-e925f349768e"> [4]

Cryptographic algorithms are utilized to encrypt messages, typically falling into two groups: block ciphers and stream ciphers.

<img width="402" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/7ce1a870-7e2b-4c3c-9c38-b9b03581f22c"> [12]

Popular symmetric block cipher algorithms: AES, Twofish, RC5/RC6, CAST, DES/DES3, Blowfish

Popular symmetric stream cipher algorithms: Salsa, Rabbit, Chacha20, Scream, RC4 

**Asymmetric encryption** utilizes a public key and a private key in encryption/decryption.

The private key should remain confidential, while the public key should be shared.

If Bob wants to send a message to Alice:

1) Bob uses Alice's public key to encrypt the message and sends it to Alice.
2) Alice receives and decrypts it using her private key, which only she possesses.
3) This ensures confidentiality, as only Alice has the private key capable of decrypting the message.

<img width="417" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/c489654e-4368-448e-be23-c6b95b4fc7a7"> [4]

**Key exchange** also utilizes asymmetric encryption:

1) Bob creates a symmetric key.
2) Bob encrypts this symmetric key with Alice's public key.
3) Bob sends it to Alice.
4) Alice decrypts it using her private key.

Popular asymmetric encryption algorithms: RSA, DSA, ECDSA, ElGamal, DH/DHKE, and ECDH.

The common way to measure encryption strength is via key length; the assumption is that keys are essentially random, which means that the keyspace is defined by the number of bits in a key.

**Hashing** is used to transform bulk data into a fixed-length string of characters, which is not reversible and is mainly used to support integrity and authenticity verification.

For example, calculating the hash of the message "Stream Connect" and "Stream Connect!" using SHA-256 generates the following digest:

<img width="817" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/e68921ad-d60d-442e-9cb9-58fabb2bf0e5">

Even with a slight change, the digest is entirely different, as can be seen in the examples, making it very hard to extract the original content.

Popular hashing algorithms: MD5, SHA-1, SHA-256, SHA-3 (SHA3-256, SHA3-512), bcrypt, Argon2, RIPEMD-160, Whirlpool, BLAKE2, and SipHash.

Another use for asymmetric encryption is **digital signatures**:

1) Bob creates a message and calculates its hash.
2) The digest is encrypted using Bob's private key, which generates the digital signature.
3) The message and the digital signature are sent to Alice.
4) Alice decrypts the digital signature using Bob's public key, calculates the digest of the message, and compares both to determine if the message was changed in transit.
5) Non-repudiation is provided because Bob can't deny that he sent the message, since only he has his private key to sign the digest of the message.

<img width="340" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/b3bb90c2-034e-4031-9190-fc7df05f0622"> [4]

To confirm the integrity of the sent message, its hash is transmitted alongside the message. Upon receiving the message, the recipient calculates the hash of the received message and compares it to the transmitted hash. If the hashes match, it confirms that the message wasn't tampered with in transit:

<img width="323" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/04baa18b-a64b-4ed0-ac21-fbe2faec6940"> [4]

But, a Man-in-the-Middle (MITM) attacker could alter the message and then recalculate its hash to match the new content:

<img width="387" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/548981df-0fb5-405c-b13c-7b4b96866cc1"> [4]

Because of this vulnerability to MITM attacks, Hash-based Message Authentication Code (**HMAC**) is often used instead:

1) Both Alice and Bob already have an established secret HMAC key.
2) Both use this HMAC key to derive two keys.
3) If Bob wants to send a message to Alice, he combines the message with one of these keys and calculates the hash of both.
4) Then, he combines this resulting digest with the other key and calculates the hash of both again.
5) Bob sends the message and the digest to Alice.
6) Alice receives and calculates the hash of the message with one of the keys, then combines the resulting digest with the other key and compares it to the digest received.

Using HMAC in this way helps to ensure the integrity and authenticity of the message, as it relies on a shared secret key between the sender and receiver.

<img width="612" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/7065ab80-2bab-4556-946b-81a8d533697d"> [6]

Since the MITM doesn't know the shared secret key, they may be able to modify the message and recalculate the digest, but it won't be accepted by Alice without using the shared key in the hash calculation.

This provides integrity (ensuring the message wasn't modified) and authentication (using the shared secret key) for data transfers between Alice and Bob.

To summarize, digital signatures are more commonly used for ensuring non-repudiation, while HMAC is used for verifying integrity and authenticity.

HMAC is generally faster than digital signatures because it involves symmetric cryptography, whereas digital signatures often require more computational resources due to asymmetric cryptography.

### PKI

**Certificate Authorities** (CAs) are entities responsible for issuing digital certificates that verify the ownership of a public key by an entity, such as a server, website, organization, or individual.

Any instance of a Client/Server/CA is part of a **Public Key Infrastructure** (PKI).

The CA represents the root of trust in a PKI because its digital certificate is pre-installed or pre-configured as a trusted authority in client systems and applications.

CAs possess their own trusted self-signed certificate along with their respective public and private keys.

To issue a certificate:

1) A server sends a Certificate Signing Request (CSR) to the CA, which contains the server's public key signed with the server's private key.
2) The CA inspects and validates the information in the CSR.
3) Based on this information, the CA creates an X.509 certificate, signs it using the CA's private key, and sends it to the server.

<img width="300" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/fd0ab6da-3be3-45c9-b103-7b12c3af5ea4"> [7]

When a client wants to connect to the server:

1) The client requests the server's certificate.
2) The server sends its certificate, which was generated by the CA.
3) Since the client already has the CA certificate installed, it uses the public key in this certificate to verify the signature in the server's certificate (which was signed using the CA's private key).
4) If the signature is valid, the server is authenticated.

<img width="612" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/a87db627-0204-4be0-a9c5-37dc78c2f4af"> [4]

A Certificate Revocation List (CRL) is a list of digital certificates that have been revoked by the Certificate Authority (CA) before their scheduled expiration date and is used within the PKI to check the validity of certificates.

The Online Certificate Status Protocol (OCSP) is a protocol used for checking the revocation status of digital certificates in real-time, providing a more efficient and scalable alternative to CRLs, which require regular distribution and updating.

### SSL/TLS 

A **cipher suite** is a selection of cryptographic primitives and other parameters that define exactly how security will be implemented. This selection is defined by the following attributes:

- $\textcolor{red}{Key \ exchange \ method}$
- $\textcolor{turquoise}{Authentication \ method}$
- $\textcolor{green}{Encryption \ algorithm}$
- $\textcolor{goldenrod}{MAC \ algorithm}$

For example:

<img width="612" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/b81beb9f-6ff0-49e4-af36-3bb9e887cfa4">

During the TLS handshake, the client and server agree on the protocols used in cipher suites.

Overview of the TLS handshake: [2]

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/74a98186-ceb2-4751-8984-973261add1a4" width="500">

1. **Client Hello** -> The client sends:
      - The best TLS version it supports.
      - A random number.
      - Session ID.
      - A list of the cipher suites it supports.
      - Extensions (additional features).

2. **Server Hello** -> The server communicates the selected connection parameters:
      - Selected TLS version.
      - Random number.
      - Session ID.
      - Selected cipher suite.
      - Extensions.

3. **Certificate** -> The server sends the certificate chain and must ensure that it sends a certificate appropriate for the $\textcolor{turquoise}{authentication \ method}$ in the selected cipher suite.
      - For example, the public key algorithm must match that used in the suite.

4. **Server Key Exchange** -> Carries additional data needed for key exchange:
      - Its contents vary and depend on the negotiated cipher suite.

5. **Server Hello Done** -> A signal that the server has sent all intended handshake messages.

6. **Client Key Exchange** -> Establishes the shared session keys (symmetric encryption and HMAC keys) depending on the $\textcolor{red}{key \ exchange \ method}$ in the cipher suite.
      - For RSA, for example:
         - The client generates the Pre-Master-Secret, which is encrypted with the server's public key and sent to the server.
         - Then, the Pre-Master-Secret is used to derive the Master Secret in both the client and server.
         - The Master Secret combined with the client's and the server's random (which both client and server have) generates the session keys.
         - Now, both client and server have the $\textcolor{green}{symmetric \ encryption}$ key and the $\textcolor{goldenrod}{HMAC}$ key for this session.
         - Actually, 2 symmetric encryption keys and 2 HMAC keys are generated (both client and server have these 4 keys).
         - One is used for client -> server communication and the other for server -> client communication.

7. **Change Cipher Spec** -> A signal that the sending side obtained enough information to manufacture the connection parameters, generated the encryption keys, and is switching to encryption.

8. **Finished** -> A signal that the handshake is complete.
      -  Carries the verify_data field, which is a hash of all handshake messages as each side saw them mixed in with the newly negotiated master secret.
      -  Done via a pseudorandom function (PRF), which is designed to produce an arbitrary amount of pseudorandom data.
         - verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))

### DNSSEC

How DNS works:

<img width="600" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/6228cd65-c4a4-40b1-8a03-1709f4579a35">

DNS records:

<img width="430" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/c4f6bdfa-0cf8-434c-bec6-31604e583932"> [3]

DNS records often have a Time-to-Live (TTL) value, which specifies how long the information can be cached by DNS resolvers. After the TTL expires, the resolver must query the authoritative name server again to refresh the information.

Back when DNS was invented, the developers were focused on making DNS work without worrying whether it was secure or not.

For example, Alice makes a request to the DNS server to get the IP address of Bob's server

<img width="247" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/f694460b-58db-450b-8eb6-a07d73d67af1"> [3]

But Trudy could spoof the DNS cache to modify Bob's DNS record with her IP address:

<img width="242" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/41418e26-27b6-4e80-8879-1f3a47b9e67f"> [3]

Alice, unaware of this, would enter Trudy's website instead, making her susceptible to further attacks.

Trudy would execute this attack in the following way:

<img width="536" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/9447227c-3ff3-4ad0-a4ad-99dc2e41a5aa"> [3]

Domain Name System Security Extensions (**DNSSEC**) is a set of security extensions to DNS, adding cryptographic integrity and authentication to DNS data, addressing vulnerabilities in the original DNS protocol and enhancing its security. 

DNSSEC records:

<img width="442" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/21ce2b4a-f0c3-47c5-974c-bc53891810fd"> [8]

Resource Record Set (RR set) is a set of records with the same type and the same zone (e.g., A records, MX records, DS records).

Resource Record Signature (RRSIG) contains digital signatures for other RR sets in the zone, each covering a specific set of DNS records and is signed using the private ZSK corresponding to the DNSKEY record.

The private Zone Signing Key (ZSK) is used to sign RR sets within a DNS zone, generating digital signatures for RR sets (RR set RRSIGs), ensuring their integrity and authenticity.

The private Key Signing Key (KSK) is used to sign the DNSKEY records (used to verify the authenticity of other DNSSEC-signed records) within a DNS zone, generating digital signatures for the DNSKEY records (DNSKEY RRSIGs), establishing the chain of trust in DNSSEC.

The public ZSK and public KSK are included in zone file as a DNSKEY record.

DS records contain the digest of the public KSK of the subordinate zone (child zone).

DNSSEC diagram:

<img width="695" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/5ab12839-8ad8-41ff-bd05-fa4ed25a066c">

Root query response (3):

1. The Root's DNSKEY RR set contains the public KSK and ZSK for the Root zone.
      - Integrity is verified by decrypting the DNSKEY RRSIG with the public KSK and comparing it with the DNSKEY RR set.
2. The Root's DS Record contains the hash of the public KSK for the subordinate zone (TLD).
      - Integrity is verified by decrypting the DS RRSIG with the public ZSK and comparing the digests.

*The DNS recursive resolver has a set of pre-installed root KSKs that it trusts, comparing it to the given public KSK in the DNSKEY RR set to establish trust and verify the zone.

TLD query response (5):

1. The TLD's DNSKEY RR set contains the public KSK and ZSK for the TLD zone.
      - Integrity is verified by decrypting the DNSKEY RRSIG with the public KSK and comparing it with the DNSKEY RR set.
2. The TLD's DS Record contains the hash of the public KSK for the subordinate zone (Authoritative).
      - Integrity is verified by decrypting the DS RRSIG with the public ZSK and comparing the digests.

*The DNS recursive resolver compares the digest of the TLD's public KSK (obtained in the previous query) with the public KSK in the DNSKEY RR set to establish trust and verify the zone.

Authoritative query response (7):

1. The Authoritative's DNSKEY RR set contains the public KSK and ZSK for the Authoritative zone.
      - Integrity is verified by decrypting the DNSKEY RRSIG with the public KSK and comparing it with the DNSKEY RR set.
2. The Authoritative's A RR set contains IPv4 addresses of the requested domain name.
      - Integrity is verified by decrypting the A RRSIG with the public ZSK and comparing both.

*The DNS recursive resolver compares the digest of the Authoritative's public KSK (obtained in the previous query) with the public KSK in the DNSKEY RR set to establish trust and verify the zone.

### HTTP/2

According to the RFC 9113[9] - **HTTP/2**:

"HTTP/2 enables a more efficient use of network resources and a reduced latency by introducing field compression and allowing multiple concurrent exchanges on the same connection"

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/0fdd9dc5-90d4-4990-b4a7-db17c8580c6a" width="400"> [10]

"Multiplexing of requests is achieved by having each HTTP request/response exchange associated with its own stream. Streams are largely independent of each other, so a blocked or stalled request or response does not prevent progress on other streams."

"In a multiplexed protocol like HTTP/2, prioritizing allocation of bandwidth and computation resources to streams can be critical to attaining good performance. A poor prioritization scheme can result in HTTP/2 providing poor performance."

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/708826c1-0e42-4aa9-b800-ba86677c4d97" width="400"> [10]

"HTTP/2 provides an optimized transport for HTTP semantics. HTTP/2 supports all of the core features of HTTP but aims to be more efficient than HTTP/1.1."

<img width="284" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/cf298883-1d23-43ad-80ce-39a683bd357c"> [10]

Features overview:

<img width="426" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/68213345-c9ff-4c4f-b0c9-fd53e904fd76"> [11]

### IPv6

IPv6 is a replacement for IPv4, using 128 bits addresses instead of 32 bits.

Some of the changes include mandatory support for IPSec, simplification of the header and support for multicast communication by default.

With the use of IPv6, the use of Classless Inter-Domain Routing (CIDR), the Dynamic Host Configuration Protocol (DHCP), and Network Address Translation (NAT) becomes dispensable, as they are not suitable for optimizing the efficiency of computer networks.

IPv6 header:

<img width="242" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/845b4526-9d8e-40dd-acdc-22eb2470b622"> [3]

Optional extension headers:

<img width="297" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/ab233af1-0896-4fe4-951c-78bb9725605b"> [3]

In order to support the IPv4 and IPv6 transition:

+ Tunneling: "Among them are ways to automatically configure the tunnels that carry IPv6 over the IPv4 Internet, and ways for hosts to automatically find the tunnel endpoints."

+ Dual-stack: "Dual-stack hosts have an IPv4 and an IPv6 implementation so that they can select which protocol to use depending on the destination of the packet."

# Practice

At the end of this project, the following results will be achieved: [5]

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/f05269ab-503c-4de8-84c8-d7b7da5023af" width="500">

During the next steps, each of the tests will be explained.

### Setting up a VM and IPv6 in GCP
To host the Apache Web Server, we'll create an Ubuntu VM in GCP.

Alternatively, the Web server could be created locally. To do so, it's necessary to open ports 80/443 on the router's firewall to allow connections:

<img width="463" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/828a7825-3344-4030-b9a3-fa512e4505d5">

With a residential network plan in Brazil, it's not possible to use it for routing external calls unless you're paying for the enterprise plan. This limitation makes the server inaccessible outside the local network it is connected to.

Ubuntu 20.04 x86/64 SSD persistent disk (10GB) VM:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/aed3fbae-7f19-4916-aa2b-dd551f894506" width="400">

By default, it is created with the default Virtual Private Cloud (VPC) network that uses an IPv4 subnet (single stack). However, it is possible to create a VPC with a subnet configured for dual stack, allowing the VM to be accessible by both IPv4 and IPv6.

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/cdd124a2-c91c-41f4-96ad-a2c5d2ce8022" width="350">


Now there are both external IPv4 and IPv6 addresses on this subnet.

To allow incoming HTTP and HTTPS traffic on the webserver, it is necessary to create firewall rules on ports 80 and 443 to permit traffic on these ports from/to any source/destination address: 0.0.0.0/0 for IPv4 and ::/0 for IPv6.

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/46867f50-c764-4958-98ec-3de8b60b50b0" width="145">

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/247c4f6a-c297-4cde-b9e3-c8e0731668e8" width="127">

Then, simply configure the VM to use this VPC and subnet instead:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/fd12a898-5eb4-43d8-8628-35afab9719f5" width="700">

Tests associated:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/3ab0b843-40f6-4f05-b31c-ae985eccc606" width="500">

```
1) Two or more name servers of your domain have an IPv6 address.

Technical details:
Name server	                IPv6 address	        IPv4 address
ns-cloud-e4.googledomains.com.	2001:4860:4802:38::6e	216.239.38.110
ns-cloud-e1.googledomains.com.	2001:4860:4802:32::6e	216.239.32.110
ns-cloud-e3.googledomains.com.	2001:4860:4802:36::6e	216.239.36.110
ns-cloud-e2.googledomains.com.	2001:4860:4802:34::6e	216.239.34.110

SIDN (.nl TLD registry) require each .nl domain to have at least two name servers.

2) All name servers, that have an AAAA record with IPv6 address, are reachable over IPv6.

3) At least one AAAA record with IPv6 address for your web server..

Technical details:
Web server	                IPv6 address	        IPv4 address
trabalhoredesstreamconnect.xyz	2600:1900:40f0:bc10::	34.151.207.183
Test explanation:

4) It is possible to connect to your web server(s) over IPv6 on any available
   ports (80 and/or 443).

5) Your website on IPv6 seems to be the same as your website on IPv4.

HTTP (port 80) and/or HTTPS (port 443) over IPv4 are also available over IPv6;
HTTP headers (such as a redirect header) over IPv4 are also received over IPv6;
```

*These results become available after setting up the A and AAAA records in Google Cloud DNS.

### Setting up DNS records with Google Cloud DNS and Namecheap

Buying and registering the domain name "trabalhoredesstreamconnect.xyz" ("networks-project-streamconnect.xyz") in Namecheap:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/52f29ed1-ff17-4049-81f7-682a81b9aa8c" width="550">

Creating a DNS zone in GCP (child zone):

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/56f54d13-6ce4-48ec-a4c7-d03565e0d747" width="600">

Name Server (NS) records:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/af3a127e-d413-4653-9a98-271d4c0f6be3" width="340">

Storing the NS RRs in Namecheap (parent zone):

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/4db8340f-0bbe-45b4-9346-9abfaf500dd6" width="600">

The parent zone, responsible for delegating authority for a subdomain, includes NS records specifying the authoritative DNS servers for the delegated subdomain. In this case, Namecheap is the TLD server and the parent zone, while GCP DNS is the Authoritative Domain Server and the child zone.

Canonical Name (CNAME) record with www.trabalhoredesstreamconnect.xyz:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/14c8c272-8e81-40cd-8134-e6c3aeb3e762" width="300">

A record with the external IPv4 address assigned to the VM instance:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/988ffe12-b099-4603-be8f-7d02b678bc57" width="300">

AAAA record with the external IPv6 address assigned to the VM instance:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/27f31b50-94c3-4df9-8eb0-cb59f6becea9" width="300">

Start of Authority (SOA) record:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/442a6dca-4b69-4813-b48d-8cbc84ed5bc6" width="300">

DNS Zone:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/7861e0ea-8209-478a-a7aa-56fdf49c694e" width="450">

### Setting up DNSSEC in Google Cloud DNS and Namecheap

DNSKEY record:

<img width="461" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/47461d5d-51c8-459b-9bf3-897260890e86">

256 is the public ZSK and 257 is the public KSK.

Delegation Signer (DS) record:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/ef16e327-ad9b-49fe-a49d-cffe7172cafb" width="400">

Storing the DS record in Namecheap (parent zone):

<img width="600" alt="Screenshot 2024-03-01 at 18 46 46" src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/fd13a034-c447-4eba-849d-693bbb3732ff">

DS records contain the digest of the public KSK of the subordinate zone (GCP DNS), establishing the chain of trust.

Now DNSSEC is set up for the domain.

Tests associated:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/5e0ffb0d-b7be-4014-b996-c0910d79fa42" width="400">

```
1) Your domain (SOA record) is DNSSEC signed.

2) Your domain is secure, because its DNSSEC signature is valid.

Domain	                        Status
trabalhoredesstreamconnect.xyz	secure

If a domain name redirects to another signed domain name via CNAME, then we also check if
the signature of the CNAME domain name is valid.
```

Other tests:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/fbc80a54-48e7-42fc-bdfa-dfc93d40508d" width="500">

### Setting up the Apache server in a VM in GCP

Downloading Apache2 on Ubuntu:

```
sudo apt install apache2
sudo systemctl enable --now apache2
systemctl status apache2
```
<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/d3ba0f66-622d-4d48-8e83-b5e9a4df0bd0" width="500">

Apache diretory(/etc/apache2):

```
apache2.conf    conf-enabled  magic           mods-enabled  sites-available
conf-available  envvars       mods-available  ports.conf    sites-enabled
```

Creating a virtual site:

```
cd /etc/apache2/sites-available
sudoedit StreamConnect.conf
```

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/7543fd08-9543-43cf-81d6-fd45eac922fd" width="300">

The server with the domain name that was bought in Namecheap is configured on ports 80 and 443. The website source code is located in "/var/www/html" (document root), where a databases project called Stream Connect is cloned. This project includes a website running a MySQL database.

An .htaccess file is created in the document root to redirect the initial access to the index page. In the case of the project used, it is index.ejs:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/62300bd5-2a74-4043-8ada-bf0a4f51aa0a" width="200">

To make Apache recognize index.ejs as an index page, index.ejs is added to the directory indexes:

```
sudoedit /etc/apache2/mods-available/catdir.conf
```

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/e723724e-e886-44cb-9372-3b0bf1e215c1" width="550">

Activating the site:

```
sudo a2ensite StreamConnect.conf
```

The following two commands can be used during the deployment of the webserver:

Checking if the apache2 syntax is ok:

```
apachectl configtest
```

Restarting apache2 to see the effects:

```
sudo systemctl restart apache2
```

Accessing the website:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/206aaa39-ebf4-4b7d-98f3-6dce445a1978" width="500">

*The image above was taken during the attempt to set up the server in a local VM instead of creating it inside GCP.

The padlock indicates that the website is not secure and should not be trusted: it is running over HTTP and does not have HTTPS set up according to OSE guidelines.

Using Wireshark to capture the HTTP packet after clicking on Login:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/b87d2ae0-f3ea-4182-94e9-5f0127098073" width="300">

The HTTP POST packet was captured, and both the username and password "SenhaSegura" ("SafePassword") were captured in plaintext.

### Setting up TLS in Apache

Requesting a certfifcate and automatically configuring it on Apache2 using Let's encrypt:

```
sudo certbot --apache -d trabalhoredesstreamconnect.xyz
```

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/c53ad334-6b4f-48e5-b892-f3ef96d3508a" width="600">

Let's Encrypt is a Certificate Authority (CA), and the image above shows the Certificate Signing Request (CSR), which includes details such as the email address and other required information. Afterwards, the certificate chain was generated.

fullchain.pem:

<img width="506" alt="Screenshot 2024-03-03 at 01 22 40" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/741ed304-9e58-4566-973e-dda99f5861ad">

<img width="508" alt="Screenshot 2024-03-03 at 01 23 21" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/adb14460-6261-4f24-a89f-2c9ed110d47d">

privatekey.pem:

<img width="508" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/881c14f4-0b31-4077-9255-3aef4c5cd088">

*Do not share the private key of a server (in this case, the server will be deleted after the project is completed).

Including the SSL certificate chain and private key .pem files in Apache2:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/1ff5bdbe-6b21-4ecd-8ad0-144282b5a2bd" width="550">

Upon accessing the website, the certificates can be seen:

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/de214483-2151-468d-b5d1-17fb87ef544e" width="340">


A SHA-256 fingerprint is a cryptographic hash value computed using SHA-256. By comparing the fingerprint obtained from a website to a known value, users can verify the authenticity and integrity of the certificate and the public key.

We can use a Python script to extract the SHA-256 fingerprints and the public key from the fullchain.pem file that was shown before:

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib

# Read the PEM file
with open("./fullchain.pem", "rb") as f:
    pem_data = f.read()

# Parse the PEM data
certificates = x509.load_pem_x509_certificate(pem_data, default_backend())

# Extract the public key and certificate
public_key = certificates.public_key()

# Get the public key bytes
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Get the certificate data in DER format
certificate_bytes = certificates.public_bytes(serialization.Encoding.DER)

# Compute the SHA-256 fingerprints
public_key_sha256 = hashlib.sha256(public_key_bytes).hexdigest()
certificate_sha256 = hashlib.sha256(certificate_bytes).hexdigest()

print("\nPublic Key SHA-256 fingerprint:", public_key_sha256)
print("Certificate SHA-256 fingerprint:", certificate_sha256)

print("Public Key:")
print(public_key_bytes)
```
Running the script provided by ChatGPT, the public key and certificate SHA-256 fingerprints match the ones in the browser:

<img width="588" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/31886078-09a8-4ae2-8f08-472a675be109">

And the public key of the server is successfully extracted.

<img width="357" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/e2e23d56-cbe7-4beb-b942-04cd0fed8a7f">

Tests associated:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/feaf75b5-f769-430f-84a5-b2e85253c509" width="500">

```
1) The trust chain of your website certificate is complete and signed by a trusted root
   certificate authority.

2) The digital signature of your website certificate uses secure parameters.

The verification of certificates makes use of digital signatures. To guarantee the
authenticity of a connection, a trustworthy algorithm for certificate verification
must be used. The algorithm that is used to sign a certificate is selected by its
supplier. The certificate specifies the algorithm for digital signatures that is
used by its owner during the key exchange. It is possible to configure
multiple certificates to support more than one algorithm.

The security of ECDSA digital signatures depends on the chosen curve. The security
of RSA for encryption and digital signatures is tied to the key length of the public
key.

3) Your website certificate is signed using a secure hash algorithm.

Hash functions for certificate verification.

Good: SHA-512, SHA-384, SHA-256
Insufficient: SHA-1, MD5

4) The domain name of your website matches the domain name on your website certificate.
```

Tests associated with the next changes:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/c00f7d83-c653-4f8e-86ff-9a61d35603e2" width="600">

Selecting supported versions of SSL/TLS for Apache2:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/cceb49b7-be0b-4fe5-a3a3-9f3803c5b9f8" width="600">

```
1) Your web server supports secure TLS versions only.

A web server may support more than one TLS version.

Note that browser makers have announced that they will stop supporting
TLS 1.1 and 1.0. This will cause websites that do not support TLS 1.2
and/or 1.3 to be unreachable.

Version

Good: TLS 1.3
Sufficient: TLS 1.2
Phase out: TLS 1.1 and 1.0
Insufficient: SSL 3.0, 2.0 and 1.0

2) Your web server supports secure ciphers only.

An algorithm selection consists of ciphers for four cryptographic functions:
1) key exchange, 2) certificate verification, 3) bulk encryption, and
4) hashing. A web server may support more than one algorithm selection.

Good:

ECDHE-ECDSA-AES256-GCM-SHA384 (TLS_AES_256_GCM_SHA384 in 1.3)
ECDHE-ECDSA-CHACHA20-POLY1305 (TLS_CHACHA20_POLY1305_SHA256 in 1.3)
ECDHE-ECDSA-AES128-GCM-SHA256 (TLS_AES_128_GCM_SHA256 in 1.3)
ECDHE-RSA-AES256-GCM-SHA384 (TLS_AES_256_GCM_SHA384 in 1.3)
ECDHE-RSA-CHACHA20-POLY1305 (TLS_CHACHA20_POLY1305_SHA256 in 1.3) 
ECDHE-RSA-AES128-GCM-SHA256 (TLS_AES_128_GCM_SHA256 in 1.3) 

3) Your web server enforces its own cipher preference ('I'), and offers ciphers
in accordance with the prescribed ordering ('II').

I. Server enforced cipher preference: The web server enforces its own cipher
preference while negotiating with a web browser, and does not accept any
preference of the web browser;

II. Prescribed ordering: Ciphers are offered by the web server in accordance
with the prescribed order where 'Good' is preferred over 'Sufficient' over
'Phase out' ciphers.

```

Setting up cipher suites that the server can negotiate:

```
sudoedit /etc/letsencrypt/options-ssl-apache.conf
SSLCipherSuite  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305::ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384
```

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/9bbeab11-ba52-4e0e-aa68-a0f38232c26f" width="600">

```
4) Your web server supports secure parameters for Diffie-Hellman key exchange.

ECDHE: The security of elliptic curve Diffie-Hellman (ECDHE) ephemeral key exchange
depends on the used elliptic curve. We check if the bit-length of the used elliptic
curves is a least 224 bits. Currently we are not able to check the elliptic curve
name.

DHE: The security of Diffie-Hellman Ephemeral (DHE) key exchange depends on the
lengths of the public and secret keys used within the chosen finite field group. 

RSA as an alternative: Besides ECDHE and DHE, RSA can be used for key exchange.
RSA is considered as 'good' for certificate verification.

5) Your web server supports a secure hash function to create the digital signature
   during key exchange.

The web server uses a digital signature during the key exchange to prove ownership
of the secret key corresponding to the certificate. The web server creates this
digital signature by signing the output of a hash function.

SHA2 support for signatures

Good: Yes (SHA-256, SHA-384 or SHA-512 supported)
Phase out: No (SHA-256, SHA-384 of SHA-512 not supported)
```

Disabling TLS compression:

```
sudo a2dismod deflate
sudo /etc/init.d/apache2 restart
```

```
6) Your web server does not support TLS compression.

The use of compression can give an attacker information about the secret parts
of encrypted communication. An attacker that can determine or control parts of
the data sent can reconstruct the original data by performing a large number
of requests. TLS compression is used so rarely that disabling it is generally
not a problem.
```

By default SSLInsecureRenegotiation is turned off in /etc/apache2/mods-available/ssl.conf:

<img width="600" alt="Screenshot 2024-03-03 at 02 58 37" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/cfa5ef89-4ea1-4337-be78-c23ec6533d32">

```
7) Your web server supports secure renegotiation.

Older versions of TLS (prior to TLS 1.3) allow forcing a new handshake. This
so-called renegotiation was insecure in its original design. The standard
was repaired and a safer renegotiation mechanism was added. The old version
is since called insecure renegotiation and should be disabled.
```

Apache 2.2.15 or greater running with OpenSSL 0.9.8l or lower disables client-initiated renegotiation completely.

```
8) Your web server does not allow for client-initiated renegotiation.

Allowing clients to initiate renegotiation is generally not necessary
and opens a web server to DoS attacks inside a TLS connection. An attacker
can perform similar DoS attacks without client-initiated renegotiation by
opening many parallel TLS connections, but these are easier to detect and
defend against using standard mitigations. Note that client-initiated
renegotiation impacts availability and not confidentiality.
```

Other test that ran successfully by default:
```
9) Your web server does not support 0-RTT.

0-RTT is an option in TLS 1.3 that transports application data during
the first handshake message. 0-RTT does not provide protection against
replay attacks at the TLS layer and therefore should be disabled. Although
the risk can be mitigated by not allowing 0-RTT for non-idempotent requests,
such a configuration is often not trivial, reliant on application logic and
thus error prone.

If your web server does not support TLS 1.3, the test is not applicable.
For web servers that support TLS 1.3, the index / page of the website is
fetched using TLS 1.3 and the amount of early data support indicated by the
server is checked. When more than zero, a second connection is made re-using
the TLS session details of the first connection but sending the HTTP request
before the TLS handshake (i.e. no round trips (0-RTT) needed before application
data to the server). If the TLS handshake is completed and the web server
responds with any non-HTTP 425 Too Early response, then the web server is
considered to support 0-RTT.
```

SSL stampling:

```
sudoedit /etc/apache2/sites-available/default-ssl.conf
SSLStaplingCache shmcb:/tmp/stapling_cache(128000)
```

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/a669af9a-a865-4a27-9bf6-247e8c1dc55e" width="600">

```
10) Your web server supports OCSP stapling and the data in the response is valid.

The web browser can verify the validity of the certificate presented by the web
server by contacting the certificate authority using the OCSP protocol. OCSP
provides a certificate authority with information on browsers communicating to
the web server: this may be a privacy risk. A web server can also provide OCSP
responses to web browsers itself through OCSP stapling. This solves this privacy
risk, does not require connectivity between web browser and certificate authority,
and is faster.

When connecting to your web server we use the TLS Certificate Status extension to
request OCSP data be included in the server response. If your web server includes
OCSP data in the response we then verify that the OCSP data is valid i.e. correctly
signed by a known certificate authority. Note: we do not use the OCSP data to
evaluate the validity of the certificate.
```

Tests associated with the next changes:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/3ddf329e-bb3f-48b3-a164-e80a12db40c8" width="600">

Setting up HSTS:

rewrite.load and headers.load should be at /etc/apache/mods-enabled:

<img width="807" alt="Screenshot 2024-03-03 at 03 19 20" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/dce78cd4-1c68-4d7b-9562-2f3f366d75bc">

if they're not there:

```
a2enmods rewrite
a2enmods headers
```

Then:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/8f51a9c6-faad-44c2-be81-0a152df40e23" width="600">

```
1) Your website offers HTTPS.

HTTPS guarantees the confidentiality and integrity of the exchanged information.
Because it is situation depended how (privacy) sensitive and valuable information
is, a secure HTTPS configuration is important for every website. Even trivial,
public information could be extremely sensitive and valuable for a user. 

2) Your web server automatically redirects visitors from HTTP to HTTPS on the same
   domain.

In case of redirecting, a domain should firstly upgrade itself by redirecting to
its HTTPS version before it may redirect to another domain. This also ensures that
the HSTS policy will be accepted by the web browser. Examples of correct redirect
order:

http://example.nl ⇒ https://example.nl ⇒ https://www.example.nl
http://www.example.nl ⇒ https://www.example.nl

3) Your web server does not support HTTP compression.

HTTP compression makes the secure connection with your webserver vulnerable for
the BREACH attack. However HTTP compression is commonly used to make more efficient
use of available bandwidth. Consider the trade-offs involved with HTTP compression.
If you choose to use HTTP compression, verify if it is possible to mitigate related
attacks at the application level. An example of such a measure is limiting the extent
to which an attacker can influence the response of a server.

Good: No compression
Sufficient: Application-level compression (in this case HTTP compression)
Insufficient: TLS compression

4) Your web server offers an HSTS policy.

Browsers remember HSTS per (sub) domain. Not adding a HSTS header to every (sub) domain
(in a redirect chain) might leave users vulnerable to MITM attacks. 

We consider a HSTS cache validity period of at least 1 year (max-age=31536000) to be
sufficiently secure. A long period is beneficial because it also protects infrequent
visitors. However if you want to stop supporting HTTPS (which is generally a poor idea),
you will have to wait longer until the validity of the HSTS policy in all browsers that
visited your website, has expired.
```

Tests associated with the next changes:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/4df1a691-e585-4aca-b511-222ca10b280c" width="600">

Setting header protection:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/5fca2cd3-d131-454c-85c0-68350ed99ea0" width="600">

```
1) Your web server offers securely configured X-Frame-Options.

With this HTTP header you let web browsers know whether you want to allow your website
to be framed or not. Prevention of framing defends visitors against attacks like
clickjacking. We consider the following values to be sufficiently secure:

DENY (framing not allowed); or
SAMEORIGIN (only framing by your own website allowed).

2) Your web server offers X-Content-Type-Options.

With this HTTP header you let web browsers know that they must not do 'MIME type
sniffing' and always follow the Content-Type as declared by your web server.
The only valid value for this HTTP header is nosniff. When enabled, a browser will
block requests for style and script when they do not have a corresponding Content-Type
(i.e. text/css or a 'JavaScript MIME type' like application/javascript).

'MIME type sniffing' is a technique where the browser scans the content of a file to
detect the format of a file regardless of the declared Content-Type by the web server.
This technique is vulnerable to the so-called 'MIME confusion attack' in which the
attacker manipulates the content of a file in a way that it is treated by the browser
as a different Content-Type, like an executable.
```

Protection against XSS:

<img width="999" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/11c3f93c-b4b9-44f9-b941-ea924b9275de">

```
3) Your web server offers Content-Security-Policy (CSP) and does not use certain insecure
   CSP settings.

CSP guards a website against content injection attacks including cross-site scripting (XSS).
By using CSP to configure an 'allowlist' with sources of approved content, you prevent
browsers from loading malicious content of attackers.

4) Your web server offers a Referrer-Policy with a policy value that is sufficiently secure
and privacy-protecting.

With this policy your webserver instructs browsers if, what and when referrer data should be
sent to the website the user is navigating to from your website. This referrer data is sent
in the Referer header by the browser to the website the user is navigating to. This
navigation does not necessarily have to be cross-domain.

The data in the Referer header is usually used for analytics and logging. However there can
be privacy and security risks. The data could be used e.g. for user tracking and the data
could leak to third parties who eavesdrop the connection. The HTTP header for
Referrer-Policy allows you to mitigate these risks by controlling and even minimizing the
sending of referrer data.

To prevent leaking of sensitive data through URLs, please make sure URLs of your website
do not contain personal or otherwise sensitive data (like personal names or passwords).
```

StreamConnect.conf:

```
<VirtualHost *:80>
        ServerName trabalhoredesstreamconnect.xyz 
        ServerAlias trabalhoredesstreamconnect.xyz
        DocumentRoot "/var/www/html/StreamConnect/views/pages"
        RewriteEngine on
        RewriteCond %{SERVER_NAME} =trabalhoredesstreamconnect.xyz 
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<VirtualHost *:443>
        Header Set Strict-Transport-Security "max-age=31536000"
        ServerName trabalhoredesstreamconnect.xyz
        ServerAlias trabalhoredesstreamconnect.xyz
        DocumentRoot "/var/www/html/StreamConnect/views/pages"
        Include /etc/letsencrypt/options-ssl-apache.conf
        SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
        Header always append X-Frame-Options DENY
        Header set X-XSS-Protection "1; mode=block"
        Header set X-Content-Type-Options nosniff
        Header set Referrer-Policy "no-referrer"
        Header always set Content-Security-Policy "default-src 'self';frame-src 'self; frame-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        SSLCertificateFile /etc/letsencrypt/live/trabalhoredesstreamconnect.xyz/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/trabalhoredesstreamconnect.xyz/privkey.pem
</VirtualHost>
```

Now the website successfully implements HTTPS:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/f55abcb6-0d19-475d-918b-9edd6bac636f" width="700">


Setting up HTTP/2:

```
apachectl stop
apt-get install php7.1-fpm # 
a2enmod proxy_fcgi setenvif
sudo a2enconf php7.1-fpm
sudo a2dismod php7.3
sudo a2dismod php7. 1
a2dismodmpmprefork#
sudo a2enmod mpm event #
sudo a2enmod http2
systemctl restart apache2
```

Test associated:

<img src="https://github.com/rafaelpereirad/Secure-Web-Service/assets/95055138/330f9474-578d-4a3c-8e65-820a8999f7fb" width="500">

### TLS in Wireshark

First, the DNS request comes from the local machine (192.168.0.3) to the local nameserver (192.168.0.1), returning the DNS A and AAAA records with the server's IP. Then, the TCP Three-Way Handshake establishes a connection with the server (35.247.248.231):

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/a26b6a2b-c64a-479f-bbde-3b7b055bdf40" width="700">

Checking the nameserver IP:

<img width="236" alt="Screenshot 2024-03-03 at 02 20 23" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/e4d0e65b-b7d7-4fde-b6cf-2bd2f5010798">

Then, the client and server will establish a TLS session in order to enable encrypted communication.

In Wireshark (TLS 1.3):

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/b9bd5dcb-35b1-4240-b59e-4d2efc3bde62" width="700">

According to RFC 8446, in TLS 1.3 "All handshake messages after the ServerHello are now encrypted."

To analyze the full TLS handshake, the Apache server should not support TLS 1.3.

```
 SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.3
```

Full TLS handshake:

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/74a98186-ceb2-4751-8984-973261add1a4" width="500"> [2]

In Wireshark (TLS 1.2):

<img src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/38ca3ccd-f357-48f4-81e2-3d0ebf904bb9" width="900">

Client Hello:

<img width="424" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/8b8d28c1-2149-4064-871b-47b52969673c">

In this message, the client informs the server about its capabilities and preferences:
- Version indicates the best supported TLS version (in this case, 1.2).
- Random is a 32-byte number used to prevent replay attacks, making each handshake unique.
- Session ID is unique and can be used by the server to reestablish the session.
- Cipher suites supported in order of preference.
- Compression (null in this case).
- Extensions are additional functionalities that TLS can use.

Server Hello:

<img width="624" alt="Screenshot 2024-03-02 at 20 24 10" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/28c93bad-03b2-4cce-9688-39bbc4a671c4">

The server communicates the selected parameters for the connection (depending on its capabilities). In this case:
- TLS 1.2 version
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as the cipher suite
- The server also generates its own random 32-byte number and session ID

Main Certificate:

<img width="935" alt="Screenshot 2024-03-02 at 20 27 26" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/42458225-b48a-4fdf-9814-cd12d673a0ad">

Intermediary certificate: 

<img width="932" alt="Screenshot 2024-03-02 at 20 28 46" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/0a87a6b1-c912-42c7-aaff-d80433691ec6">

The certificates must be signed with algorithms supported by the client, and each one must have its certificate chain.

Certificate Status:

<img width="800" alt="Screenshot 2024-03-02 at 20 30 03" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/9aefe6a9-bab7-4623-a877-b89ead0373c8">

OCSP is used to validate HTTPS certificates. It checks the revocation status of a certificate based on its serial number in a CA database. It serves as an alternative to the use of CRLs. In this case, the response status is successful.

Server Key exchange:

<img width="600" alt="Screenshot 2024-03-02 at 20 31 02" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/36e136aa-40b0-4d50-a2a4-b8d11c0a71ac">

Server Hello done:

<img width="304" alt="Screenshot 2024-03-02 at 20 31 33" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/9479a88c-1c30-45b2-9456-43e95148f4c8">

Client Key Exchange:

<img width="438" alt="Screenshot 2024-03-02 at 20 32 11" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/c47e8f6d-7761-4c67-b046-38f9c14b39f3">

Change Cipher Spec and Encrypted Handshake Message (Finished) from client to server:

<img width="347" alt="Screenshot 2024-03-02 at 20 34 45" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/24b90b5a-aa3f-4ca3-9283-7d9d4424dc64">

Change Cipher Spec and Encrypted Handshake Message (Finished) from server to client:

<img width="349" alt="Screenshot 2024-03-02 at 20 33 52" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/28c0ce6d-8d42-4549-8355-b8f946fd18fa">

After that, all the application data exchanged between the client and server during this session is encrypted.

### Decrypting the TLS session in Wireshark using the server's private key

Login attempt:

<img width="597" alt="Screenshot 2024-03-02 at 22 38 12" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/f2e19a6c-1c13-4e81-adce-7269934c1f10">

Diffie-Hellman (DHE) ciphers do not allow decryption of the session using the private key. For this reason, the Apache server is going to be configured to not support DHE for key exchange and instead enforce RSA:

```
SSLCipherSuite AES128-GCM-SHA256
```

New server Hello:

<img width="377" alt="image" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/01231ff9-bc4e-49c8-becc-e12f5bcff600">

Now it is using TLS_RSA_WITH_AES_128_GCM_SHA256 as the cipher suite instead of TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, as was selected before.

Edit > Preferences > Protocol > TLS:

<img width="426" alt="Screenshot 2024-03-02 at 22 18 30" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/6224d5bc-fee1-421f-a58d-3e09d6a68c52">

Edit the RSA Key List and browse to the key file, which should be privatekey.pem (the private key of the server as shown before).

Now the session is decrypted:

<img width="791" alt="Screenshot 2024-03-02 at 22 24 45" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/a2487bc2-6fea-4e7f-99ed-ab7d125399e1">

The HTTP POST is visible:

<img width="800" alt="Screenshot 2024-03-02 at 22 27 33" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/eb1540e3-2014-4249-8e83-162d9c4e4670">

Following the TLS stream, the username "user123" and password "SecurePassword" that were typed can now be seen as plaintext:

<img width="600" alt="Screenshot 2024-03-02 at 22 26 51" src="https://github.com/rafaelpereirad/secure-web-server/assets/95055138/99a1f279-19c8-43fe-965f-dcb681eb42c8">

# References:

[1] OSE documentation. Available at: https://github.com/InternetSociety/ose-documentation?tab=readme-ov-file

[2] Ristić, I. (2014). Bulletproof SSL and TLS: Chapter 2. Lightning Source Inc. ISBN-13: 978-1907117046.

[3] Tanenbaum, A. S., & Wetherall, D. J. (2010). Computer Networks: Chapters 5, 7 & 8. Pearson. ISBN-13: 978-0132126953.

[4] Stallings, W. (2013). Cryptography and Network Security: Principles and Practice: Chapters 2, 3, 9, 12, 13, & 14. Pearson. ISBN-13: 978-0133354690.

[5] Internet.nl: website test. Available at: https://internet.nl/site/trabalhoredesstreamconnect.xyz/2658447/#

[6] Hash-vs-Mac, Baeldung. Available at: https://www.baeldung.com/cs/hash-vs-mac

[7] PKI. Available at: https://www.tutorialspoint.com/cryptography/public_key_infrastructure.html

[8] Hands-on DNS and DNSSEC, Md. Abdul Awal. Available at: https://www.slideshare.net/bdnog/handson-dnssec-deployment

[9] IETF RFC 9113 - HTTP/2, M. Thomson, Ed., C. Benfield, E. Available at: https://datatracker.ietf.org/doc/html/rfc9113#section-1-6

[10] What Is HTTP/2 And How Is It Different From HTTP/1?, Mukhadin Beschokov. Available at: https://www.wallarm.com/what/what-is-http-2-and-how-is-it-different-from-http-1

[11] HTTP/2 is here, let’s optimize!, Ilya Grigorik. Available at: https://pingdom.com/blog/http2-new-protocol/

[12] Security+ course, ACI Learning ITProTV. Available at: https://www.acilearning.com/products/itpro/
