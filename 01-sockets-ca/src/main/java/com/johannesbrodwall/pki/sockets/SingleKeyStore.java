package com.johannesbrodwall.pki.sockets;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Properties;

public class SingleKeyStore {
    private String keyAlias;
    private final File filename;
    private final char[] storePassword;
    private final char[] keyPassword;
    private final KeyStore keyStore;

    public SingleKeyStore(Properties properties, String prefix) throws GeneralSecurityException, IOException {
        this(
                properties.getOrDefault(prefix + ".alias", prefix).toString(),
                new File(properties.getOrDefault(prefix + ".keystore.filename", prefix + ".p12").toString()),
                properties.getProperty(prefix + ".keystore.password").toCharArray(),
                properties.getProperty(prefix + ".key.password").toCharArray()
        );
    }

    public SingleKeyStore(String keyAlias, File filename, char[] storePassword, char[] keyPassword) throws GeneralSecurityException, IOException {
        this.keyAlias = keyAlias;
        this.filename = filename;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        keyStore = KeyStore.getInstance("pkcs12");
        if (filename.exists()) {
            load();
        }
    }

    public TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    public KeyManager[] getKeyManagers() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword);
        return keyManagerFactory.getKeyManagers();
    }

    public String getSubjectDN() throws KeyStoreException {
        return getCertificate().getSubjectDN().getName();
    }

    private X509Certificate getCertificate() throws KeyStoreException {
        return (X509Certificate) keyStore.getCertificate(keyAlias);
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
    }

    public void setEntry(PrivateKey key, Certificate certificate) throws KeyStoreException {
        keyStore.setKeyEntry(keyAlias, key, keyPassword, new Certificate[] { certificate });
    }

    public void load() throws IOException, GeneralSecurityException {
        try (FileInputStream stream = new FileInputStream(filename)) {
            keyStore.load(stream, storePassword);
        }
    }

    public void store() throws GeneralSecurityException, IOException {
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

}
