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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.Scanner;

public class CaMain {

    private Date validFrom = new Date();
    private long validityDays = 100;
    private Scanner scanner = new Scanner(System.in);
    private Properties properties = new Properties();
    private String caKeyStore;
    private char[] caStorePassword;
    private char[] caKeyPassword;

    public CaMain(String filename) throws IOException {
        try (FileReader reader = new FileReader(filename)) {
            properties.load(reader);
        }
        caKeyStore = properties.getProperty("ca.keystore.filename");
        caStorePassword = properties.getProperty("ca.keystore.password").toCharArray();
        caKeyPassword = properties.getProperty("ca.key.password").toCharArray();
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

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();


        Date validTo = new Date(validFrom.getTime() + validityDays * 86400000L);

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        X509CertInfo certInfo = createX509Info(validTo);
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(issuer));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(issuer));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(keyPair.getPrivate(), "SHA512withRSA");

        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("ca", keyPair.getPrivate(), caKeyPassword, new Certificate[] { certificateImpl });
        try (FileOutputStream stream = new FileOutputStream(caKeyStore)) {
                keyStore.store(stream, caStorePassword);
        }
    }

    private void createClientCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Commmon name (name of certificate)");
        String commonName = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + commonName;

        KeyStore caKeyStore = KeyStore.getInstance("pkcs12");
        try (FileInputStream stream = new FileInputStream(this.caKeyStore)) {
            caKeyStore.load(stream, caStorePassword);
        }
        X509Certificate caCertificate = (X509Certificate) caKeyStore.getCertificate("ca");
        PrivateKey caKey = (PrivateKey) caKeyStore.getKey("ca", caKeyPassword);


        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Date validTo = new Date(validFrom.getTime() + validityDays * 86400000L);

        X509CertInfo certInfo = createX509Info(validTo);
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(subject));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(caCertificate.getSubjectDN().getName()));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        certInfo.set(X509CertInfo.EXTENSIONS, new CertificateExtensions());

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(caKey, "SHA512withRSA");

        writeKeyStore(keyPair, certificateImpl, "client", "client.key.password", "client.keystore.filename", "client.keystore.password");
    }

    private void writeKeyStore(KeyPair keyPair, X509CertImpl certificateImpl, String client, String s, String s2, String s3) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(client, keyPair.getPrivate(), properties.getProperty(s).toCharArray(), new Certificate[]{certificateImpl});
        try (FileOutputStream stream = new FileOutputStream(properties.getProperty(s2))) {
            keyStore.store(stream, properties.getProperty(s3).toCharArray());
        }
    }

    private void createServerCertificateAndKey() throws GeneralSecurityException, IOException {
        System.out.println("Organization name?");
        String organization = scanner.nextLine().trim();
        System.out.println("Server hostname (used as CN - Common Name and Subject Alternative Name)");
        String hostname = scanner.nextLine().trim();
        String subject = "O=" + organization + ",CN=" + hostname;

        KeyStore caKeyStore = KeyStore.getInstance("pkcs12");
        try (FileInputStream stream = new FileInputStream(this.caKeyStore)) {
            caKeyStore.load(stream, caStorePassword);
        }
        X509Certificate caCertificate = (X509Certificate) caKeyStore.getCertificate("ca");
        PrivateKey caKey = (PrivateKey) caKeyStore.getKey("ca", caKeyPassword);


        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Date validTo = new Date(validFrom.getTime() + validityDays * 86400000L);

        X509CertInfo certInfo = createX509Info(validTo);
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(subject));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(caCertificate.getSubjectDN().getName()));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));

        CertificateExtensions extensions = new CertificateExtensions();
        GeneralNames subjectAlternativeNames = new GeneralNames();
        subjectAlternativeNames.add(new GeneralName(new DNSName(hostname)));
        extensions.set(SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(subjectAlternativeNames));
        certInfo.set(X509CertInfo.EXTENSIONS, extensions);

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(caKey, "SHA512withRSA");

        writeKeyStore(keyPair, certificateImpl, "server", "server.key.password", "server.keystore.filename", "server.keystore.password");
    }

    private X509CertInfo createX509Info(Date validTo) throws CertificateException, IOException {
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(validFrom, validTo));
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
                new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid)));
        return certInfo;
    }
}
