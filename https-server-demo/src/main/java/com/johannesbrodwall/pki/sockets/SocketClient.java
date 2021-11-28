package com.johannesbrodwall.pki.sockets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class SocketClient {
    private static final Logger logger = LoggerFactory.getLogger(SocketClient.class);
    private final SSLContext sslContext;

    public SocketClient(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    public String run(InetSocketAddress serverAddress) throws IOException {
        logger.info("Connecting to {}", serverAddress);

        Socket socket = sslContext.getSocketFactory().createSocket(serverAddress.getHostName(), serverAddress.getPort());
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        socket.getInputStream().transferTo(buffer);
        return buffer.toString();
    }
}
