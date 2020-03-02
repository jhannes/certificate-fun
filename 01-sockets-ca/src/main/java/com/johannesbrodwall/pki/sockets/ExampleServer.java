package com.johannesbrodwall.pki.sockets;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ExampleServer {

    public static void main(String[] args) throws IOException {
        new ExampleServer().start();
    }

    private void start() throws IOException {
        ServerSocket serverSocket = new ServerSocket(30001);
        while (!Thread.interrupted()) {
            try (Socket clientSocket = serverSocket.accept()) {
                handleClient(clientSocket);
            }
        }
    }

    private void handleClient(Socket clientSocket) throws IOException {
        clientSocket.getOutputStream().write("Hello world".getBytes());
    }
}
