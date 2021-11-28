
# Intro - certificates and you

1. Go to web server with invalid certificate and get message. Install CA certificate and error goes away
2. Go to web server which requires client certificate. Preferable no valid certificates are installed
3. Install certificate in the OS. Client is accepted

## Certificates in a Java client program

1. HttpsURLConnection is rejected because of invalid certificate root
2. Add SSL Context with server certificate
3. Server accepts client
4. Use to web server which requires a client certificate. Server rejects client
5. Add private key to server. Server is accepted

# Theory

1. Asymmetric encryption and RSA
2. p12 private key containers (.jks)
3. CRT files - the public part of the p12
   1. A look into
4. CSR files
   1. A look into

# Explaining the program

## Where did the server CRT come from?

1. Delete and have it regenerated at startup
2. Show that it's in the p12
3. Delete p12 and generate it from scratch - fixing the code

## Where did the client get it's p12 file?

1. Start the client and it spits out a p12 and a csr file - fixing the code
2. Upload the CSR to the server and get a CRT in return (in database?)
3. Restart the client and it reads in the crt-file and accesses the server

# Creating the keys in KeyStore Explorer



