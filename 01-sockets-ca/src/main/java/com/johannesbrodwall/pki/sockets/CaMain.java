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

    private final CertificateAuthority certificateAuthority;
    private final ZonedDateTime validFrom = ZonedDateTime.now();
    private final Scanner scanner = new Scanner(System.in);
    private final Properties properties;
    private final KeyStoreFile caKeyStoreFile;

    public CaMain(String filename) throws IOException, GeneralSecurityException {
        properties = new Properties();
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        caKeyStoreFile = new KeyStoreFile(properties, "ca", null);
        certificateAuthority = new SunCertificateAuthority(caKeyStoreFile, Period.ofDays(100));
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
        System.out.println("Common name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String issuer = "O=" + organization + ",CN=" + commonName;

        certificateAuthority.createCaCertificate(issuer, validFrom);
        caKeyStoreFile.store();
    }


    private void createClientCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Common name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + commonName;

        KeyStoreFile clientKeyStore = new KeyStoreFile(properties, "client", certificateAuthority.getCertificate());
        KeyPair keyPair = clientKeyStore.getKeyStore().generateKeyPair();
        clientKeyStore.getKeyStore().setEntry(
                keyPair.getPrivate(),
                certificateAuthority.issueClientCertificate(subject, validFrom, keyPair.getPublic())
        );
        clientKeyStore.store();
    }

    private void createServerCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Server hostname (used as CN - Common Name and Subject Alternative Name)");
        String hostname = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + hostname;

        KeyStoreFile serverKeyStore = new KeyStoreFile(properties, "server", certificateAuthority.getCertificate());
        KeyPair keyPair = serverKeyStore.getKeyStore().generateKeyPair();
        serverKeyStore.getKeyStore().setEntry(
                keyPair.getPrivate(),
                certificateAuthority.issueServerCertificate(hostname, subject, validFrom, keyPair.getPublic())
        );
        serverKeyStore.store();
    }

}
