package io.liquidpki.der;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ExamineCertificate {

    private String name;

    public ExamineCertificate(String name) {
        this.name = name;
    }

    public static void main(String[] args) throws IOException {
        //new io.liquidpki.der.ExamineCertificate("local-test-request.csr").run();
        new ExamineCertificate("local-test-certificate.crt").run();

        //DerFactory.read(readDerFile("local-test-keystore.p12")).output(System.out, "");
    }

    private static byte[] readDerFile(String name) throws IOException {
        InputStream input = new FileInputStream(name);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        input.transferTo(buffer);
        return buffer.toByteArray();
    }

    private void run() throws IOException {
        for (byte[] derBytes : readPemObjects(name)) {
            Der value = Der.parse(derBytes);
            System.out.println(value.toHexBytes());
            value.output(System.out, "");
        }
    }

    public static List<byte[]> readPemObjects(String filename) throws IOException {
        try (InputStream input = new FileInputStream(filename)) {
            return readPemObjects(input);
        }
    }

    public static List<byte[]> readPemObjects(InputStream input) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        input.transferTo(buffer);
        return readPemObjects(buffer);
    }

    public static List<byte[]> readPemObjects(ByteArrayOutputStream buffer) {
        // 🤮🤢
        List<byte[]> certificatesDer = new ArrayList<>();
        String content = new String(buffer.toByteArray());
        StringBuilder currentCertificate = null;
        for (String line : content.split("\r?\n")) {
            if (line.matches("-----BEGIN [A-Z ]+-----")) {
                if (currentCertificate != null) {
                    System.err.println("No!");
                }
                currentCertificate = new StringBuilder();
            } else if (line.matches("-----END [A-Z ]+-----")) {
                if (currentCertificate == null) {
                    System.err.println("No!");
                } else {
                    certificatesDer.add(Base64.getDecoder().decode(currentCertificate.toString()));
                    currentCertificate = null;
                }
            } else {
                if (currentCertificate == null) {
                    System.err.println("No!");
                } else {
                    currentCertificate.append(line);
                }
            }
        }
        if (currentCertificate != null) {
            System.err.println("NO!");
        }
        return certificatesDer;
    }

}
