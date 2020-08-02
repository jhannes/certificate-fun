package com.johannesbrodwall.pki.sockets;

import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Properties;
import java.util.Scanner;

public class CaMain {

    private final SingleKeyStore caStore;
    private final Date validFrom = new Date();
    private final long validityDays = 100;
    private final Scanner scanner = new Scanner(System.in);
    private final Properties properties = new Properties();
    private final KeyPairGenerator generator;

    public CaMain(String filename) throws IOException, GeneralSecurityException {
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        caStore = new SingleKeyStore(properties, "ca");
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
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

        KeyPair keyPair = generator.generateKeyPair();

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        X509CertInfo certInfo = createX509CertInfo(issuer, issuer, keyPair, extensions);

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(keyPair.getPrivate(), "SHA512withRSA");

        caStore.setEntry(keyPair.getPrivate(), certificateImpl);
        caStore.store();
    }

    private X509CertInfo createX509CertInfo(String subject, String issuer, KeyPair keyPair, CertificateExtensions extensions) throws CertificateException, IOException {
        Date validTo = new Date(validFrom.getTime() + validityDays * 86400000L);

        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(validFrom, validTo));
        certInfo.set(X509CertInfo.SERIAL_NUMBER,
                new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid)));
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(subject));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(issuer));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certInfo.set(X509CertInfo.EXTENSIONS, extensions);
        return certInfo;
    }

    private void createClientCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Commmon name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + commonName;

        KeyPair keyPair = generator.generateKeyPair();

        X509CertInfo certInfo = createX509CertInfo(subject, caStore.getSubjectDN(), keyPair, new CertificateExtensions());

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(caStore.getPrivateKey(), "SHA512withRSA");

        writeCertificateToKeystore(keyPair, certificateImpl, "client");
    }

    private void createServerCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Server hostname (used as CN - Common Name and Subject Alternative Name)");
        String hostname = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + hostname;

        KeyPair keyPair = generator.generateKeyPair();

        CertificateExtensions extensions = new CertificateExtensions();
        GeneralNames subjectAlternativeNames = new GeneralNames();
        subjectAlternativeNames.add(new GeneralName(new DNSName(hostname)));
        extensions.set(SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(subjectAlternativeNames));

        X509CertInfo certInfo = createX509CertInfo(subject, caStore.getSubjectDN(), keyPair, extensions);

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(caStore.getPrivateKey(), "SHA512withRSA");

        writeCertificateToKeystore(keyPair, certificateImpl, "server");
    }

    private void writeCertificateToKeystore(KeyPair keyPair, X509CertImpl certificateImpl, String key) throws GeneralSecurityException, IOException {
        SingleKeyStore keyStore = new SingleKeyStore(properties, key);
        keyStore.setEntry(keyPair.getPrivate(), certificateImpl);
        keyStore.store();
    }
}
