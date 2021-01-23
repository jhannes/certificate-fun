package com.johannesbrodwall.pki.sockets;

import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Properties;
import java.util.Scanner;

public class CaMain {

    private final SingleKeyStore caStore;
    private final ZonedDateTime validFrom = ZonedDateTime.now();
    private final Period validity = Period.ofDays(100);
    private final Scanner scanner = new Scanner(System.in);
    private final SingleKeyStore serverKeyStore;
    private final SingleKeyStore clientKeyStore;

    public CaMain(String filename) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        caStore = new SingleKeyStore(properties, "ca");
        serverKeyStore = new SingleKeyStore(properties, "server");
        clientKeyStore = new SingleKeyStore(properties, "client");
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        new CaMain("local-sockets.properties").start();
    }

    private void start() throws GeneralSecurityException, IOException {
        System.out.println("Choose your action:");
        System.out.println("1. Create certificate authority (local-ca.p12)");
        System.out.println("2. Create client key (local-client.p12)");
        System.out.println("3. Create server key (local-server.p12)");

        String line = scanner.nextLine().trim();
        if (line.equals("1")) {
            createCaCertificateAndKey();
        } else if (line.equals("2")) {
            createClientCertificateAndKey();
        } else if (line.equals("3")) {
            createServerCertificateAndKey();
        } else {
            System.out.println("Unknown action");
        }
    }

    private void createCaCertificateAndKey() throws IOException, GeneralSecurityException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Commmon name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String issuer = "O=" + organization + ",CN=" + commonName;

        caStore.createCaCertificate(issuer, validFrom, validFrom.plus(validity));
        caStore.store();
    }


    private void createClientCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Commmon name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + commonName;

        KeyPair keyPair = clientKeyStore.generateKeyPair();
        clientKeyStore.setEntry(
                keyPair.getPrivate(),
                caStore.issueClientCertificate(subject, validFrom, validFrom.plus(validity), keyPair.getPublic())
        );
        clientKeyStore.store();
    }

    private void createServerCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Server hostname (used as CN - Common Name and Subject Alternative Name)");
        String hostname = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + hostname;

        KeyPair keyPair = serverKeyStore.generateKeyPair();
        serverKeyStore.setEntry(
                keyPair.getPrivate(),
                caStore.issueServerCertificate(hostname, subject, validFrom, validFrom.plus(validity), keyPair.getPublic())
        );
        serverKeyStore.store();
    }

}
