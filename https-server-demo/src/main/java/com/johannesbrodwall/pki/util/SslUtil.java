package com.johannesbrodwall.pki.util;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SslUtil {
    @SuppressWarnings("RedundantThrows")
    public static List<X509Certificate> readCertificates(List<Path> certificates) throws GeneralSecurityException, IOException {
        return certificates.stream().map(ExceptionUtil.softenFunction(SslUtil::readCertificate)).collect(Collectors.toList());
    }

    public static X509Certificate readCertificate(Path crtFile) throws GeneralSecurityException, IOException {
        try (InputStream input = Files.newInputStream(crtFile)) {
            return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(input);
        }
    }

    public static KeyStore createKeyStore(PrivateKey privateKey, char[] password, X509Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(certificate.getSubjectDN().toString(), privateKey, password, new Certificate[] {certificate});
        return keyStore;
    }

    public static KeyStore loadKeyStore(Path keyStoreFile, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreFile.getFileName().toString().endsWith(".p12") ? "pkcs12" : KeyStore.getDefaultType());
        try (InputStream inputStream = Files.newInputStream(keyStoreFile)) {
            keyStore.load(inputStream, password.toCharArray());
        }
        return keyStore;
    }

    public static KeyManager[] createKeyManagers(KeyStore keyStore, char[] password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);
        return keyManagerFactory.getKeyManagers();
    }

    public static TrustManager[] createTrustManagers(List<X509Certificate> certificates) throws GeneralSecurityException, IOException {
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null, null);
        for (X509Certificate certificate : certificates) {
            trustStore.setCertificateEntry(certificate.getSubjectDN().toString(), certificate);
        }

        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        return factory.getTrustManagers();
    }

    public static SSLContext createSslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws GeneralSecurityException {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(keyManagers, trustManagers, null);
        return ctx;
    }

    public static SSLContext createSslContext(KeyStore serverKeyStore, char[] keyPassword, List<X509Certificate> certificates) throws GeneralSecurityException, IOException {
        return createSslContext(createKeyManagers(serverKeyStore, keyPassword), createTrustManagers(certificates));
    }

    public static SSLContext toSslContext(Map<String, String> config, Path keystoreFile, List<Path> trustedCertificates) throws GeneralSecurityException, IOException {
        String keyStorePassword = config.getOrDefault("keyStorePassword", "");
        String keyPassword = config.getOrDefault("keyPassword", "");
        return createSslContext(
                loadKeyStore(keystoreFile, keyStorePassword),
                keyPassword.toCharArray(),
                readCertificates(trustedCertificates)
        );
    }

    public static void saveCertificate(X509Certificate certificate, Path path) throws IOException, CertificateEncodingException {
        Files.createDirectories(path.getParent());
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            writeCertificate(writer, certificate);
        }
    }

    public static void storeKeyStore(KeyStore keyStore, Path path, String password) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        Files.createDirectories(path.getParent());
        try (OutputStream stream = Files.newOutputStream(path)) {
            keyStore.store(stream, password.toCharArray());
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
