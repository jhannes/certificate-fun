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
import java.time.Period;
import java.util.Properties;

public class ExampleClient {
    private static final Logger logger = LoggerFactory.getLogger(ExampleClient.class);

    private final SSLContext sslContext;

    public ExampleClient(SingleKeyStore clientKeyStore) throws IOException, GeneralSecurityException {
        sslContext = clientKeyStore.createSslContext();
    }

    public ExampleClient(String filename) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        CertificateAuthority caKeyStore = new SunCertificateAuthority(new KeyStoreFile(properties, "ca", null), Period.ofDays(100));
        KeyStoreFile clientKeyStore = new KeyStoreFile(properties, "client", caKeyStore.getCertificate());
        sslContext = clientKeyStore.createSslContext();
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new ExampleClient("local-sockets.properties").run(InetSocketAddress.createUnresolved("localhost", 30001));
    }

    void run(InetSocketAddress serverAddress) throws IOException {
        logger.info("Connecting to {}", serverAddress);

        Socket socket = sslContext.getSocketFactory().createSocket(serverAddress.getHostName(), serverAddress.getPort());
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        socket.getInputStream().transferTo(buffer);
        System.out.println(buffer);
    }
}
