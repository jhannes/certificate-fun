package com.johannesbrodwall.pki.sockets;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;

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
