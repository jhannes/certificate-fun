package com.johannesbrodwall.pki.sockets;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Period;
import java.time.ZonedDateTime;

class CaMainTest {
    
    @Test
    void integrationTest() throws GeneralSecurityException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        CertificateAuthority certificateAuthority = new CertificateAuthority(new SingleKeyStore("ca", "dsgnl".toCharArray(), null), Period.ofDays(1));

        ZonedDateTime now = ZonedDateTime.now();
        certificateAuthority.createCaCertificate("CN=Test Root CA,O=Certificate Fun Corp", now);

        SingleKeyStore serverKeyStore = new SingleKeyStore("server", "sdgnkslk".toCharArray(), certificateAuthority.getCertificate());
        KeyPair serverKeyPair = serverKeyStore.generateKeyPair();
        serverKeyStore.setEntry(
                serverKeyPair.getPrivate(),
                certificateAuthority.issueServerCertificate("localhost", "CN=localhost,O=Server Org", now, serverKeyPair.getPublic())
        );

        SingleKeyStore clientKeyStore = new SingleKeyStore("client", "sdgnkslk".toCharArray(), certificateAuthority.getCertificate());
        KeyPair clientKeyPair = clientKeyStore.generateKeyPair();
        clientKeyStore.setEntry(
                clientKeyPair.getPrivate(),
                certificateAuthority.issueClientCertificate("CN=Client,O=Client Org", now, clientKeyPair.getPublic())
        );

        ExampleServer server = new ExampleServer(serverKeyStore);
        new Thread(server::run).start();
        
        ExampleClient client = new ExampleClient(clientKeyStore);
        client.run(InetSocketAddress.createUnresolved("localhost", 30001));
    }
    

}