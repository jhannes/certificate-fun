package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class ExampleClient {
    private static final Logger logger = LoggerFactory.getLogger(ExampleClient.class);

    private final SingleKeyStore clientKeyStore;
    private SSLContext sslContext;

    public ExampleClient(SingleKeyStore clientKeyStore, X509Certificate caCertificate) throws IOException, GeneralSecurityException {
        this.clientKeyStore = clientKeyStore;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(clientKeyStore.getKeyManagers(), SingleKeyStore.createTrustManager(caCertificate), null);
    }

    public ExampleClient(String filename) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        SingleKeyStore caKeyStore = new SingleKeyStore(properties, "ca");
        clientKeyStore = new SingleKeyStore(properties, "client");
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(clientKeyStore.getKeyManagers(), caKeyStore.getTrustManagers(), null);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new ExampleClient("local-sockets.properties").run();
    }

    void run() throws IOException {
        InetSocketAddress serverAddress = InetSocketAddress.createUnresolved("localhost", 30001);
        logger.info("Connecting to {}", serverAddress);

        Socket socket = sslContext.getSocketFactory().createSocket(serverAddress.getHostName(), serverAddress.getPort());
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        socket.getInputStream().transferTo(buffer);
        System.out.println(buffer.toString());
    }
}
