# Certificate  fun

So, I decided to make my own Certificate Authority. Kidding. Not kidding.

Private Key Infrastructure (PKI) is what creates security on the public web and to an increasing extend on internal networks as well. Yet, most developers and operations only have a superficial understanding of the technology. I aim to lay the details of the technology bare so you can understand it at any level you want.


```plantuml

server ca "Certificate Authority"
server secure "Secure Server"

database keystore "Client Certificates"
client browser "Web Browser"

ca -> keystore: User installs .crt as Trusted Root CA
secure -> ca: Server requests certificate (csr)
secure <-- ca: Signed certificate (crt)

secure -> browser: Authorizes with certificate
browser -> keystore: Checks CA
```



## Tutorial

### Step 1: Create two key pairs and use them to authorize a simple Socket-based server

1. In the `01-sockets-ca` project, run `com.johannesbrodwall.pki.sockets.CaMain`. The program will prompt you for your action
    * First, create a Certificate Authority. This will create the file `local-ca.p12`
    * Second, create a peer key named "client". This will create the file `local-client.p12`
    * Second, create a peer key named "server". This will create the file `local-server.p12`
    * You can use [KeyStore explorer](https://keystore-explorer.org/) to examine the `*.p12`-files
2. In the `01-sockets-ca` project, run `com.johannesbrodwall.pki.sockets.ExampleServer`
3. In the `01-sockets-ca` project, run `com.johannesbrodwall.pki.sockets.ExampleClient`

You will now see the client logging out the name of the server and the server logging out the name of the client. Do an experiment:

* Use the KeyStore Explorer to remove the "CA Root Certificate" from either the client or server p12-file. This will cause the relevant party to reject the certificate of the other party. You can recreate the `p12`-file by running `CaMain` again.

### Step 2: Web certificate server

First, you need to get the certificate server running:

1. In the `02-ca-webapp`, run `com.johannesbrodwall.pki.web.CaServer`. This will start up a web server at http://localhost:10080 and https://ca-server.local:10443
2. Starting the CaServer will create a file named `local-ca.crt` on disk. You need to install this as a root certificate authority on your computer. Instructions for Windows:
   1. Find the file in Windows Explorer (in IntelliJ, select the file in Project Explorer, press Alt-F1 (Select-in) and B (Explorer)) and double click the file
   2. This will open the Certificate Viewer where you can examine the certificate file.
   3. Press "Install Certificate..." to open the Certificate Import Wizard
   4. On the second page, select "Place all certificates in the following store"  and select "Trusted Root Certificate Authorities"
   5. **You probably will have to kill all your web browser processes for the change to take effect in the browser**. Alternatively you can open an incognito browser window
3. You will need to update your `hosts`-file and add an entry of `127.0.0.1 ca-server.local` (On Windows, you can edit `c:\Windows\System32\drivers\etc\hosts` as Administrator to do this)
4. When you now go to https://ca-server.local:10443, your web browser will show the site as trusted

### Step 3: Issue certificates with the CA server

Second, you can create and use a private-key and certificate for a web server.

1. In the `03-demo-server`, run `com.johannesbrodwall.pki.web.DemoServer`. This will start up a web server at http://localhost:11080 and https://demo-server.local:11443
2. When the demo server start, it will create a file named `local-demo-server.crs`. This is a Certificate Signing Request that requires a Certificate Authority, like the one we just created to sign
3. Go to the https://ca-server.local:10443 and select "Upload a server certificate signing request"
4. You will now download a file called `local-demo-server.crt`. Place this next to `local-demo-server.csr`
5. The server will automatically import the .crt file into `local-demo-server.p12` and delete files that are no longer needed.
3. You will need to update your `hosts`-file and add an entry of `127.0.0.1 local-demo.local` (On Windows, you can edit `c:\Windows\System32\drivers\etc\hosts` as Administrator to do this)
6. You can now go to https://demo-server.local:11443 and the web browser will accept the certificate

### Step 4: Issue client signed keys with the CA server

Thirdly, you can **insecurely** create and use a private-key and certificate for the browser.

1. Go to https://ca-server.local:10443 and select "Create a certificate where the server insecurely handles the private key"
2. This will download a file named `local-web-client.p12`. You can use KeyStore Explorer to examine the p12-file
3. Install the .p12-file as a client certificate. Instructions for Windows:
   1. Find the file in Windows Explorer (in IntelliJ, select the file in Project Explorer, press Alt-F1 (Select-in) and B (Explorer)) and double click the file
   2. This will open the Certificate Viewer where you can examine the certificate file.
   3. Press "Install Certificate..." to open the Certificate Import Wizard
   4. On the second page, select "Automatically place the certificate..."
4. Go to https://demo-server.local:12443 (which was also started by `com.johannesbrodwall.pki.DemoServer`).
5. The browser will prompt you for a client certificate and you can now choose the one you just imported 

### Step 5: Sign certificates while remaining control of the private key

You can also create a secure client certificate where the private key never leaves the owners computer:

1. You have to create a certificate signing request on your operating system. Instructions for Windows:
   1. Open the start menu and type "Manage User Certificates" - open the default application
   2. Right click "Personal" on the left pane and select All Tasks > Advanced Operations > Create Custom Request... 
   3. On the screen "Select Certificate Enrollment Policy", you have to select Custom Request > Proceed without enrollment policy (this is because our simple CA-server doesn't support automatic enrollment)
   4. You can select default on next screen
   5. On the "Certificate Information" screen, you should click "Details" and "Properties"
   6. Select the pane "Private Key" and under "Key options" select "Make private key exportable"
   7. On the screen "Where do you want to save the offline request", select Browse and write a name *including the extension*, like "local-request.req"
2. Go to https://ca-server.local:10443 and select "Create a certificate from a signing request"
3. Select the request file you created in the first step
4. This will download a file with an .crt-extension. You can use KeyStore Explorer to examine the p12-file
5. Install the .crt-file as a client certificate. Instructions for Windows:
   1. Find the file in Windows Explorer and double click the file
   2. This will open the Certificate Viewer where you can examine the certificate file.
   3. Press "Install Certificate..." to open the Certificate Import Wizard
   4. On the second page, select "Automatically place the certificate..."
6. Go to https://demo-server.local:12443 (which was also started by `com.johannesbrodwall.pki.DemoServer`).
7. The browser will prompt you for a client certificate and you can now choose the one you just imported 
8. You can export the certificate to a .p12 or .pfx file which can be used by other programs. Instructions for Windows:
   1. In "Manage User Certificates", you can select Personal > Certificates. Refresh the view if you cannot see your new certificate
   2. Right click the certificate and select "All Tasks" > "Export..."
   3. Make sure you select "Yes, export the private key". If this step is disabled, you forgot to select "Make private key exportable" when you created the signing request. You have to redo the creation of the certificate to make this work (you can then delete the old certificate)
   4. On the screen "Security", you will have to enter a password. Make sure you make a note of the password, as you will use it later
   5. When you complete the export, you will have a file with a name of your choice like "local-keystore.pfx" (or whatever you choose)

### Step 6: Use client certificate in https client application

Use the signed key in a client application

1. You have created either a .p12-file from the CA-server or a .pfx-file from the operating system. These are the same format, just with different extensions. You can examine these with KeyTool Explorer to see what's inside
2. In the `06-api-client`, you can run `com.johannesbrodwall.pki.client.HttpsApiClient`. This requires a file named `local-https-client.properties`
3. You can use the file `local-https-client.properties.template` as a template. Just copy and rename it to `local-https-client.properties`
4. Input `client.keystore.file=<the name of your .pfx or .p12 file>` and `client.keystore.password=<password>`. If you created your .p12-file from ca-server, you should leave the password empty. If you exported it from your OS certificate manager, you should put the password you selected during the export
5. Run `HttpsApiClient` with the `local-https-client.properties` file updated; make sure `DemoServer` is running
6. Both the client and server will now log the name of the other party


### Node JS server

* [ ] Create openapi-generator (from hugin)
* [ ] Use https://github.com/digitalbazaar/forge to do various operations
  * [ ] Start server with .p12 file https://stackoverflow.com/a/12078490/27658
  * [ ] Create CA certificate to import in OS and use it in app
  * [ ] Create .p12-file with key and certificate
  * [ ] Read client certificate from http connection
  * [ ] Create .crt from .csr
  * [ ] Client request with key (https://stackoverflow.com/a/35478865/27658)
  * [ ] Read client key console.log(socket.getPeerCertificate(true).raw);
  
  
### Open SSL


## Johannes learning objectives

* Write a DER parser that makes sense of a .p12, a .crt and a .csr-file
  * [ ] Convert PEM to DER
  * [ ] Split DER into objects
    * [ ] Parse all OBJECT IDENTIFIERS
    * [ ] BITSTRING
    * [ ] Understand 0xa0, 0xa3 (APPLICATION tags?)
    * [ ] Factory for known tags
    * [ ] Print out x.509 certificate https://tools.ietf.org/html/rfc5280#section-4.1
* Write DER exporter that creates a .csr-file
* Get Jetty (or at least SecureServerSocket) to request client certificate from specified CAs
  * Debug SSL handshake to see what Java receives from an Nginx server or similar
* https://github.com/digitalbazaar/forge
