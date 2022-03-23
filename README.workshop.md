# Workshop: Exploring certificates with Java

## Prerequisites

* IntelliJ or Eclipse (instructions will assume IntelliJ)
* Java 11
* (Recommended: [KeyStore explorer](https://keystore-explorer.org/))


## Getting started

1. Clone [the GitHub repository](https://github.com/jhannes/certificate-fun/)
2. Add the necessary entries to you `hosts`-file (on Linux/Mac: `/etc/hosts`. On Windows: `C:\Windows\System32\drivers\etc\hosts`):
   `127.0.0.1 ca.boosterconf.local
   127.0.0.1 app.boosterconf.local`
3. Try to run all unit test. This will fail if you don't do this step above. It will also fail the first time you run it, as some tests depend on local files. Copy the contents of `target/test-data/certificates` to `src/test/resources/certificates` to run successfully
4. Run `com.johannesbrodwall.pki.ca.server.CaHttpServer` as a main class - start, but with an error message that it cannot read the certificate information. The server runs on localhost:11080, but not yet with https
5. Create a file named `pkidemo.properties` with the following contents:
  `ca.keystore=certs/ca/ca.p12
   ca.create.ifMissing=true 
   ca.create.issuerDN=O=Sopra Steria,OU=Conference talk`
6. If you go to the server at [https://localhost:11443](localhost) you be warned about an untrusted server.
7. Locate `certs/ca/ca.crt` and install it *as a Trusted Root*. Restart the browser and try [https://localhost:11443](localhost) again. You should now get access
8. Follow the rest of the workshop in `SCRIPT.md`
9. Did you enjoy this workshop? Give the repository a star on [Github](https://github.com/jhannes/certificate-fun/)

