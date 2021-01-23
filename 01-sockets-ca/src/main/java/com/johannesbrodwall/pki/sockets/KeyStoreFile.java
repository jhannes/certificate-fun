package com.johannesbrodwall.pki.sockets;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import javax.crypto.KeyGenerator;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.Properties;
import java.util.Set;

public class KeyStoreFile {

    private final File keyStoreFile;
    private final char[] keyStorePassword;
    private SingleKeyStore keyStore;

    public static KeyStore loadKeyStore(File filename, char[] password) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        try (FileInputStream stream = new FileInputStream(filename)) {
            keyStore.load(stream, password);
        }
        return keyStore;
    }

    public KeyStoreFile(Properties properties, String prefix, X509Certificate caCertificate) throws GeneralSecurityException, IOException {
        this(
                properties.getOrDefault(prefix + ".alias", prefix).toString(),
                new File(properties.getOrDefault(prefix + ".keystore.filename", prefix + ".p12").toString()),
                properties.getProperty(prefix + ".keystore.password").toCharArray(),
                properties.getProperty(prefix + ".key.password").toCharArray(),
                caCertificate
        );
    }


    public KeyStoreFile(String alias, File keyStoreFile, char[] keyStorePassword, char[] keyPassword, X509Certificate caCertificate) throws IOException, GeneralSecurityException {
        this.keyStoreFile = keyStoreFile;
        this.keyStorePassword = keyStorePassword;
        keyStore = new SingleKeyStore(loadKeyStore(keyStoreFile, keyStorePassword), alias, keyPassword, caCertificate);
    }

    public SingleKeyStore getKeyStore() {
        return keyStore;
    }

    public void store() throws GeneralSecurityException, IOException {
        keyStore.store(keyStoreFile, keyStorePassword);
    }

    public SSLContext createSslContext() throws IOException, GeneralSecurityException {
        return keyStore.createSslContext();
    }
}
