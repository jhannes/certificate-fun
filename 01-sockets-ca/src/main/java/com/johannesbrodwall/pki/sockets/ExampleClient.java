package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.PersistentMBean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Properties;

public class ExampleClient {
    private static final Logger logger = LoggerFactory.getLogger(ExampleClient.class);
    private final Properties properties = new Properties();

    public ExampleClient(String filename) throws IOException {
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new ExampleClient("local-sockets.properties").start();
    }

    private void start() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(properties.getProperty("client.keystore.filename")), properties.getProperty("client.keystore.password").toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, properties.getProperty("client.key.password").toCharArray());

        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(new FileInputStream(properties.getProperty("ca.keystore.filename")), properties.getProperty("ca.keystore.password").toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        InetSocketAddress serverAddress = InetSocketAddress.createUnresolved("localhost", 30001);
        logger.info("Connecting to {}", serverAddress);

        Socket socket = sslContext.getSocketFactory().createSocket(serverAddress.getHostName(), serverAddress.getPort());
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        socket.getInputStream().transferTo(buffer);
        System.out.println(new String(buffer.toByteArray()));
    }
}
