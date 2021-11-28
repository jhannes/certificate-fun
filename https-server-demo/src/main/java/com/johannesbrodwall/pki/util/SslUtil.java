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
import java.security.KeyPair;
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

    public static KeyStore createKeyStore(PrivateKey privateKey, char[] keyPassword, X509Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(certificate.getSubjectDN().toString(), privateKey, keyPassword, new Certificate[] {certificate});
        return keyStore;
    }

    public static KeyStore loadKeyStore(Path keyStoreFile, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(keyStoreFile.getFileName().toString().endsWith(".p12") ? "pkcs12" : KeyStore.getDefaultType());
        try (InputStream inputStream = Files.newInputStream(keyStoreFile)) {
            keyStore.load(inputStream, password.toCharArray());
        }
        return keyStore;
    }

    public static void storeKeyStore(KeyStore keyStore, Path path, String password) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        Files.createDirectories(path.getParent());
        try (OutputStream stream = Files.newOutputStream(path)) {
            keyStore.store(stream, password.toCharArray());
        }
    }

    public static KeyManager[] createKeyManagers(KeyPair serverKeyPair, X509Certificate serverCertificate) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
        return createKeyManagers(createKeyStore(serverKeyPair.getPrivate(), null, serverCertificate), null);
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

    public static SSLContext toSslContext(Map<String, String> config, Path keystoreFile, List<Path> trustedCertificates) {
        try {
            String keyStorePassword = config.getOrDefault("keyStorePassword", "");
            String keyPassword = config.getOrDefault("keyPassword", "");
            return createSslContext(
                    loadKeyStore(keystoreFile, keyStorePassword),
                    keyPassword.toCharArray(),
                    readCertificates(trustedCertificates)
            );
        } catch (GeneralSecurityException | IOException e) {
            throw ExceptionUtil.softenException(e);
        }
    }

    public static void writeCertificationRequest(byte[] serverCsr, Path path) throws IOException {
        writePemFile(path, serverCsr, "CERTIFICATE REQUEST");
    }

    public static void writeCertificate(X509Certificate certificate, Path path) throws IOException, CertificateEncodingException {
        writePemFile(path, certificate.getEncoded(), "CERTIFICATE");
    }

    private static void writePemFile(Path path, byte[] encoded, String label) throws IOException {
        Files.createDirectories(path.getParent());
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            writePemFile(writer, encoded, label);
        }
    }

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc7468">PKIX Textual Encodings</a>
     * */
    private static void writePemFile(Writer writer, byte[] rawCrtText, final String label) throws IOException {
        writer.write("-----BEGIN " + label + "-----\n");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        writer.write(encodedCertText);
        writer.write("\n-----END CERTIFICATE-----");
        writer.flush();
    }
}
