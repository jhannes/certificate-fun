# Intro - certificates and you

The goal of this demo is to show all the steps needed to have an untrusted server with an untrusted client and
no certificate authority until the client and server 

Here is a web server with no established trust. I will show the steps from your computer and your programs know
nothing about the certificates until trust is established.

`pkidemo.properties` has the configuration for the certificate authority (CA), the server and the client.
Initially all lines are commented out.

### Important

* **Firefox** users: Firefox has a separate certificate store from the OS under
  Settings > Private & Security > Security > View Certificates. You have to install CA and client certificates here
  if you use Firefox
* **Chrome** users: The browser process has to be restarted to find new CA and client certificates in the operating
  system


## Getting the browser to trust a new CA

1. When I start `com.johannesbrodwall.pki.server.CaHttpServer`, it complains that it needs to know where to store
   the information about the certificate authority. I specify `ca.keyStore` and `ca.keyStorePassword` for the storage 
   of the file with the key and certificate and I also give the CA a name, which is called the `ca.create.issuerDN`
   (Distinguished Name). Finally, I specify that it can be created if missing `ca.create.ifMissing` 
3. When I start the server, we can see that the file is created. In addition, the server exports a `.crt` with the same
   name.
4. I can now go to https://localhost:8443, but I get the message that the CA is untrusted. In the browser, we can
   examine the Certification Path and see that the CA that issued this certificate is not trusted
5. I can install the `ca.crt` file in my operating system as a Trusted Root Authority. The browser will now trust the
   server, ***but watch out** Chrome needs to be restarted to refresh the Root CAs* (actually restarting the
   incognito browser is enough)

## Host name validation

1. Looking further down in `pkidemo.properties`, we find `ca.https.address`. You won't have so much use of a server
   running only on localhost, so change it to `ca.https.address=javazone.ssldemo.local:8443`
2. If you go to https://localhost:8443 you will now get a warning from the browser that the hostname doesn't
   match the certificate
3. If you go to https://javazone.ssldemo.local:8443 you probably will not get any luck. But update your hosts-file
   (`C:\Windows\System32\drivers\etc\hosts` on Windows) and you will work better
4. If you examine the certificate, you will see that the name java.ssldemo.local occurs both in the CN (common name)
   and as an extended certificate attribute

## Creating a new server

1. When I start `HttpsDemoServer`, this server currently doesn't have a host
   certificate. It will start on http://localhost:10080, though
2. I can update `https.address=server.local:10443`. Since it doesn't have a certificate, the server is still
   not starting https. But it generates a .key with the private key and a .csr-file with the certification request.
3. Upload the .csr file to https://javazone.ssldemo.local:8443 to generate a certificate, which should be placed
   according to the configuration in `pkidemo.properties`
4. The server will now start the https-port and you can access it at https://server.local:10443

## Browser client validation

1. If you change `https.wantClientAuth=true` and restart the browser (sorry), the server will prompt you for a
   certificate. But it will not accept any certificate you already have because it requires the same CA as we
   just created. Press escape and you will still come to the server
2. Go to "Show client certificate" and the server will respond that it has no client certificate
3. Let's ask the server to generate a key and certificate for us. Enter `CN=whatever` as Common name and "Generate p12-file"
4. You will now get a file downloaded on your computer. Install it as a personal certificate
5. When you restart the browser you can now see your client certificate

**Note**: In this scenario, the server has the chance to sniff the client certificate, which is not ideal.
We will look at ways to avoid this.

## Theory: What's certificates and Public Key Infrastructure really about?

The trust established in a Public Key Infrastructure is based on a few base assumptions:

* There exists keypairs with the mathematical property that what is encrypted by one of the members of the pair
  can be decrypted with the other and vice-versa, while knowing one doesn't make it possible to uncover the other.
  A metaphor of padlocks and keys can be imagined.
* Each party can freely share their public key but must guard their private key
* Since the relationship between the keys is symmetric, this can be used both for encryption and for authentication.
  If you have the public key of a party, you can determine if a message was actually sent from that party. This
  is called a message signature
* But a problem remains: With many parties, how do you get the public key of a party that you don't know already?
  The solution is a Certificate Authority. A client must somehow establish that it trusts the public key of a
  trusted third party
* The job of the certificate authority is to issue certificates to parties. When the certificate authority is
  satisfied about the identity of a party, that party can receive a certificate which is a message with it's
  name and public key, signed by the certificate authority. Others who trust the same CA can then verify that
  this is the correct public key

There are still a few hard problems in a PKI: How do you establish the trust on the CAs and how does CAs determine
the identity of the parties before issuing a certificate. These are hard problems, but there exists a few
simple cases:

* Operating systems ship with the certificates of a list of well known CAs
* CAs like letsencrypt issues challenges to parties to place files at a URL for a hostname they claim
  to control. This means that while creating certificates, letsencrypt would be vulnerable to DNS poisoning
  attacks


## Java client server validation

1. `pkidemo.properties` has client URL. Set `client.url=https://javazone.ssldemo.local:8443/demo/test`, when
   you run `com.johannesbrodwall.pki.client.HttpsDemoClient` you get an exception
2. This is because even though your OS trusts the CA, Java maintains its own list of certificate authorities.
   We can update the Java-installation, but that is normally not practical. Instead, we set the configuration
   `client.key.trustedCertificates=ca.crt`
3. The client can now connect to the server, but the server hasn't established the authentication for the client.
   We can take a p12-file generated from the CA web server and specify it as `client.key.keyStore=client/client.pfx`.
   The server will now establish the identity of the client

## The way forward:

### Use a Certification Request to generate a certificate

When we generated the p12-file from the server, the server generated both the private key and the certificate and sent
both to the client. In our case the server doesn't retain a copy of the private key (or the certificate for that
matter), but the client has no guarantee of this. A better approach to maintain trust barriers is for the client
to send a Certification Request to the server. The certification request contains the identification requested
by the client as well as it's public key. The server can issue a certificate with the public key

In Windows, the program Manage User Certificates can be used to generate the certification request.

There's also a code example of how to generate a certification request in Java in 
`com.johannesbrodwall.pki.util.SunCertificateUtil.createHostnameCsr`


### How to use this in practice

We use certification issuance to keep track of all certificate clients of our server. Even though we terminate
SSL on the HTTP proxy layer, we issue our own certificates in Java. This way we have the identity of all
certificates in a database and can maintain privileges for computer users associated with each certificate


## Summary

1. Empty pkidemo.properties
2. Get ca up and running
3. Get https server up and running
4. Get https client up and running


