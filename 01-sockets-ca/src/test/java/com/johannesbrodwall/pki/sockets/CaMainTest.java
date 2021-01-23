package com.johannesbrodwall.pki.sockets;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
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
        
        SingleKeyStore caKeyStore = new SingleKeyStore("ca", new File("target/ca-keystore.p12"), "maslnglk".toCharArray(), "sdgnkslk".toCharArray());
        SingleKeyStore clientKeyStore = new SingleKeyStore("client", new File("target/client-keystore.p12"), "maslnglk".toCharArray(), "sdgnkslk".toCharArray());
        SingleKeyStore serverKeyStore = new SingleKeyStore("ca", new File("target/server-keystore.p12"), "maslnglk".toCharArray(), "sdgnkslk".toCharArray());

        ZonedDateTime now = ZonedDateTime.now();
        caKeyStore.createCaCertificate("CN=Test Root CA,O=Certificate Fun Corp", now, now.plus(Period.ofDays(1)));

        KeyPair serverKeyPair = serverKeyStore.generateKeyPair();
        serverKeyStore.setEntry(
                serverKeyPair.getPrivate(),
                caKeyStore.issueServerCertificate("localhost", "CN=localhost,O=Server Org", now, now.plus(Period.ofDays(1)), serverKeyPair.getPublic())
        );
        
        KeyPair clientKeyPair = clientKeyStore.generateKeyPair();
        clientKeyStore.setEntry(
                clientKeyPair.getPrivate(),
                caKeyStore.issueClientCertificate("CN=Client,O=Client Org", now, now.plus(Period.ofDays(1)), clientKeyPair.getPublic())
        );

        ExampleServer server = new ExampleServer(serverKeyStore, caKeyStore.getCertificate());
        new Thread(server::run).start();
        
        ExampleClient client = new ExampleClient(clientKeyStore, caKeyStore.getCertificate());
        client.run();
    }
    

}