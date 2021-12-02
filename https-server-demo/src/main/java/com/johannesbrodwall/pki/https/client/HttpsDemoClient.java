package com.johannesbrodwall.pki.https.client;

import org.actioncontroller.config.ConfigMap;
import org.actioncontroller.config.ConfigObserver;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.johannesbrodwall.pki.util.SslUtil.toSslContext;

public class HttpsDemoClient {
    private SSLContext sslContext;
    private URL url;

    public static void main(String[] args) throws IOException {
        HttpsDemoClient testClient = new HttpsDemoClient();
        new ConfigObserver("pkidemo")
                .onPrefixedValue("client.key", testClient::getSslContext, testClient::setSslContext)
                .onUrlValue("client.url", new URL("https://localhost"), testClient::setUrl);
        System.out.println(testClient.fetch("/demo/echo"));
    }

    private void setUrl(URL url) {
        this.url = url;
    }

    private SSLContext getSslContext(ConfigMap configMap) {
        Path keyStore = configMap.optionalFile("keyStore").filter(Files::isRegularFile).orElse(null);
        return toSslContext(configMap, keyStore, configMap.listFiles("trustedCertificates"));
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
