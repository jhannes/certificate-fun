package com.johannesbrodwall.pki.sockets;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Set;

public class SingleKeyStore {

    private final KeyPairGenerator generator;

    private final String keyAlias;
    private final char[] keyPassword;
    private final X509Certificate caCertificate;
    private final KeyStore keyStore;

    public SingleKeyStore(String keyAlias, char[] keyPassword, X509Certificate caCertificate) throws GeneralSecurityException, IOException {
        this(emptyKeyStore(), keyAlias, keyPassword, caCertificate);
    }

    private static KeyStore emptyKeyStore() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null);
        return keyStore;
    }

    public SingleKeyStore(KeyStore keyStore, String keyAlias, char[] keyPassword, X509Certificate caCertificate) throws GeneralSecurityException {
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
        this.caCertificate = caCertificate;
        this.keyStore = keyStore;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
    }

    public SSLContext createSslContext() throws IOException, GeneralSecurityException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(getKeyManagers(), createTrustManager(caCertificate), null);
        return sslContext;
    }

    public static TrustManager[] createTrustManager(X509Certificate certificate) throws IOException, GeneralSecurityException {
        if (certificate == null) {
            return null;
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null);
        trustStore.setCertificateEntry(certificate.getSubjectDN().getName(), certificate);
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();
    }
    
    public KeyManager[] getKeyManagers() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword);
        return keyManagerFactory.getKeyManagers();
    }

    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
    }

    public String getSubjectDN() throws KeyStoreException {
        return getCertificate().getSubjectDN().getName();
    }

    public X509Certificate getCertificate() throws KeyStoreException {
        return (X509Certificate) keyStore.getCertificate(keyAlias);
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
    }

    public void setEntry(PrivateKey key, Certificate certificate) throws KeyStoreException {
        keyStore.setKeyEntry(keyAlias, key, keyPassword, new Certificate[] { certificate });
    }

    public void store(File filename, char[] storePassword) throws GeneralSecurityException, IOException {
        try (FileOutputStream stream = new FileOutputStream(filename)) {
            keyStore.store(stream, storePassword);
        }
    }

    public void exportCertificate() throws KeyStoreException, IOException, CertificateEncodingException {
        try (FileWriter writer = new FileWriter(keyAlias + ".crt")) {
            writeCertificate(writer, getCertificate());
        }
    }

    public static void writeCertificate(Writer writer, X509Certificate certificate) throws IOException, CertificateEncodingException {
        writer.write("-----BEGIN CERTIFICATE-----\n");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        writer.write(encodedCertText);
        writer.write("\n-----END CERTIFICATE-----");
        writer.flush();
    }

    public boolean isIssuedBy(String issuerDN) throws KeyStoreException {
        return getCertificate().getIssuerDN().toString().equals(issuerDN);
    }

    public void exportSigningRequest() throws IOException, GeneralSecurityException {
        Set<String> criticalExtensionOIDs = getCertificate().getCriticalExtensionOIDs();

        for (String oid : criticalExtensionOIDs) {
            byte[] extensionValue = getCertificate().getExtensionValue(oid);
        }
//        PKCS9Attribute.EXTENSION_REQUEST_OID
  //      new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, )


        PKCS10 certificationRequest = new PKCS10(getCertificate().getPublicKey());
//        certificationRequest.getAttributes().setAttribute(X509CertInfo.EXTENSIONS,
//                new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, ext));

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey());
        certificationRequest.encodeAndSign(new X500Name(getSubjectDN()), signature);

        try (PrintStream output = new PrintStream(new FileOutputStream(keyAlias + ".csr"))) {
            certificationRequest.print(output);
        }
    }

}
