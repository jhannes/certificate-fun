package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class ExampleServer {
    private static final Logger logger = LoggerFactory.getLogger(ExampleServer.class);

    private Properties properties = new Properties();

    public ExampleServer(String filename) throws IOException {
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new ExampleServer("local-sockets.properties").start();
    }

    private void start() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(properties.getProperty("server.keystore.filename")), properties.getProperty("server.keystore.password").toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, properties.getProperty("server.key.password").toCharArray());

        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(new FileInputStream(properties.getProperty("ca.keystore.filename")), properties.getProperty("ca.keystore.password").toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        SSLServerSocket serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(30001);
        serverSocket.setWantClientAuth(true);
        while (!Thread.interrupted()) {
            logger.info("Waiting for connections: {}", serverSocket.getLocalSocketAddress());
            try (Socket clientSocket = serverSocket.accept()) {
                logger.info("Connected: {}", clientSocket);
                handleClient(clientSocket);
            } catch (IOException e) {
                logger.error("Failed to handle socket", e);
            }
        }
    }

    private void handleClient(Socket clientSocket) throws IOException {
        String peer = "world";
        if (clientSocket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) clientSocket;
            Certificate[] certificates = sslSocket.getSession().getPeerCertificates();
            logger.info("{} certificates: {}", "Peer", certificates);
            peer = ((X509Certificate)certificates[0]).getSubjectDN().getName();
        }
        logger.info("Responding");
        clientSocket.getOutputStream().write(("Hello " + peer).getBytes());
    }
}
