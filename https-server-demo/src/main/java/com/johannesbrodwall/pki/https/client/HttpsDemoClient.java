package com.johannesbrodwall.pki.https.client;

import org.actioncontroller.config.ConfigMap;
import org.actioncontroller.config.ConfigObserver;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;

public class HttpsDemoClient {
    private SSLContext sslContext;
    private URL url;

    public static void main(String[] args) throws IOException {
        HttpsDemoClient testClient = new HttpsDemoClient();
        new ConfigObserver("pkidemo")
                .onPrefixedValue("client.key", testClient::getSslContext, testClient::setSslContext)
                .onUrlValue("client.url", new URL("https://localhost"), testClient::setUrl);
        System.out.println(testClient.fetch(""));
    }

    private void setUrl(URL url) {
        this.url = url;
    }

    private SSLContext getSslContext(ConfigMap configMap) throws GeneralSecurityException, IOException {
        Optional<Path> keyStorePath = configMap.optionalFile("keyStore");
        String keyStorePassword = ((Map<String, String>) configMap).getOrDefault("keyStorePassword", "");
        String keyPassword = ((Map<String, String>) configMap).getOrDefault("keyPassword", "");
        Optional<Path> trustedCertificatePaths = configMap.optionalFile("trustedCertificates");

        // Private key
        KeyManager[] keyManagers = null;

        if (keyStorePath.isPresent()) {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            try (InputStream inputStream = Files.newInputStream(keyStorePath.get())) {
                keyStore.load(inputStream, keyStorePassword.toCharArray());
            }
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            keyManagers = keyManagerFactory.getKeyManagers();
        }

        // Certificate Authority
        TrustManager[] trustManagers = null;
        if (trustedCertificatePaths.isPresent()) {
            KeyStore trustStore = KeyStore.getInstance("pkcs12");
            trustStore.load(null, null);

            X509Certificate certificate;
            try (InputStream input = Files.newInputStream(trustedCertificatePaths.get())) {
                certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(input);
            }
            trustStore.setCertificateEntry("ca", certificate);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trustStore);
            trustManagers = factory.getTrustManagers();
        }

        // SSL Context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);
        return sslContext;
    }

    public String fetch(String spec) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(this.url, spec).openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        int responseCode = connection.getResponseCode();
        if (responseCode >= 400) {
            throw new IOException("Response code " + responseCode + ": " + connection.getResponseMessage());
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        connection.getInputStream().transferTo(buffer);
        return buffer.toString();
    }

    public void setSslContext(SSLContext sslContext) {
        this.sslContext = sslContext;
    }
}
