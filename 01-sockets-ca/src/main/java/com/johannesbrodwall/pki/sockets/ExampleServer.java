package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.util.Properties;

public class ExampleServer {
    private static final Logger logger = LoggerFactory.getLogger(ExampleServer.class);

    private final SSLContext sslContext;

    public ExampleServer(SingleKeyStore serverKeyStore) throws GeneralSecurityException, IOException {
        sslContext = serverKeyStore.createSslContext();
    }

    public ExampleServer(String filename) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        CertificateAuthority caKeyStore = new CertificateAuthority(new KeyStoreFile(properties, "ca", null), Period.ofDays(100));
        KeyStoreFile serverKeyStore = new KeyStoreFile(properties, "server", caKeyStore.getCertificate());
        sslContext = serverKeyStore.createSslContext();
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new ExampleServer("local-sockets.properties").start();
    }

    public void start() throws IOException, GeneralSecurityException {
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

    public void run() {
        try {
            start();
        } catch (IOException | GeneralSecurityException e) {
            logger.error("An error occurred. Shutting down", e);
        }
    }
}
