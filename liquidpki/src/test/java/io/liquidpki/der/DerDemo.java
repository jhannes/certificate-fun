package io.liquidpki.der;

import io.liquidpki.pkcs12.Pkcs12KeyStore;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class DerDemo {

    private String filename;

    public DerDemo(String filename) {
        this.filename = filename;
    }

    public static void main(String[] args) throws IOException {
        new DerDemo(args[0]).print();
    }

    private void print() throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (FileInputStream file = new FileInputStream(filename)) {
            file.transferTo(buffer);
        }
        byte[] bytes = buffer.toByteArray();

        new Pkcs12KeyStore(Der.parse(bytes)).output(System.out, "");
    }

}
