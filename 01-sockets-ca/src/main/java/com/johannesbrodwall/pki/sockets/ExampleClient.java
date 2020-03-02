package com.johannesbrodwall.pki.sockets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ExampleClient {
    public static void main(String[] args) throws IOException {
        new ExampleClient().start();
    }

    private void start() throws IOException {
        Socket socket = new Socket("localhost", 30001);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        socket.getInputStream().transferTo(buffer);
        System.out.println(new String(buffer.toByteArray()));
    }
}
