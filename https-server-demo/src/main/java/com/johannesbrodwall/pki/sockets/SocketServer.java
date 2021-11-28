package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SocketServer {
    private static final Logger logger = LoggerFactory.getLogger(SocketServer.class);
    private final SSLContext sslContext;
    private int port = 0;
    private SSLServerSocket serverSocket;

    public SocketServer(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void run() {
        try {
            runServer();
        } catch (IOException e) {
            logger.error("An error occurred. Shutting down", e);
        }
    }

    private void runServer() throws IOException {
        serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(port);
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

    public int getPort() {
        return serverSocket != null ? serverSocket.getLocalPort() : port;
    }
}
