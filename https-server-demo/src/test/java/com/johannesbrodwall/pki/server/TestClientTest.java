package com.johannesbrodwall.pki.server;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.util.SunCertificateUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

import static com.johannesbrodwall.pki.util.SslUtil.createKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.createSslContext;
import static com.johannesbrodwall.pki.util.SslUtil.loadKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.readCertificate;
import static com.johannesbrodwall.pki.util.SslUtil.storeKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.writeCertificate;
import static com.johannesbrodwall.pki.util.SslUtil.writeCertificationRequest;
import static org.assertj.core.api.Assertions.assertThat;

class TestClientTest {

    private KeyPairGenerator generator;
    private String org = "JohannesCorp " + UUID.randomUUID();

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
    }

    @Test
    void shouldEchoClientCertificate() throws Exception {
        InetSocketAddress httpsAddress = new InetSocketAddress("javazone.ssldemo.local", 0);

        Path directory = Path.of("src/test/resources/certificates/");
        X509Certificate caCertificate = readCertificate(directory.resolve("ca.crt"));

        KeyStore serverKeyStore = loadKeyStore(directory.resolve("server.p12"), "");
        X509Certificate serverCertificate = (X509Certificate) serverKeyStore.getCertificate(serverKeyStore.aliases().nextElement());
        SSLContext serverSslContext = createSslContext(serverKeyStore, null, List.of(caCertificate));

        KeyStore clientKeyStore = loadKeyStore(directory.resolve("client.p12"), "");
        X509Certificate clientCertificate = (X509Certificate) clientKeyStore.getCertificate(clientKeyStore.aliases().nextElement());
        SSLContext clientSslContext = createSslContext(clientKeyStore, null, List.of(caCertificate));

        TestServer server = new TestServer();
        server.setHttpsConfiguration(httpsAddress, serverSslContext);
        server.start();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(server.getURL(), "/demo/test").openConnection();
        connection.setSSLSocketFactory(clientSslContext.getSocketFactory());

        assertThat(connection.getResponseCode()).isEqualTo(200);
        assertThat(firstCertificate(connection.getServerCertificates()).getSubjectDN())
                .isEqualTo(serverCertificate.getSubjectDN());
        assertThat(connection.getInputStream()).hasContent("Hello " + clientCertificate.getSubjectDN());
    }

    @Test
    void shouldGenerate() throws Exception {
        CertificateAuthority ca = new SunCertificateAuthority(Period.ofDays(10), generator.generateKeyPair(), "CN=Johannes CA, O=" + org, ZonedDateTime.now());

        String clientSubjectDN = "CN=JavaZone Demo Cert" + UUID.randomUUID() + ", OU=dev, O=" + org;
        InetSocketAddress httpsAddress = new InetSocketAddress("javazone.ssldemo.local", 0);

        Path directory = Path.of("target/test-data/certificates/");

        X509Certificate caCertificate = ca.getCaCertificate();
        writeCertificate(caCertificate, directory.resolve("ca.crt"));
        caCertificate = readCertificate(directory.resolve("ca.crt"));

        KeyPair serverKeyPair = generator.generateKeyPair();
        String serverSubjectDN = "CN=" + httpsAddress.getHostName() + ",O=" + org;

        byte[] serverCsr = SunCertificateUtil.createHostnameCsr(serverKeyPair, serverSubjectDN, httpsAddress.getHostName());
        writeCertificationRequest(serverCsr, directory.resolve("server.csr"));

        X509Certificate serverCertificate = ca.issueCertificate(serverCsr, ZonedDateTime.now());
        assertThat(serverCertificate.getSubjectAlternativeNames()).containsOnly(List.of(2, httpsAddress.getHostName()));
        KeyStore serverKeyStore = createKeyStore(serverKeyPair.getPrivate(), null, serverCertificate);
        storeKeyStore(serverKeyStore, directory.resolve("server.p12"), "");
        serverKeyStore = loadKeyStore(directory.resolve("server.p12"), "");

        KeyPair clientKeyPair = generator.generateKeyPair();
        byte[] clientCsr = SunCertificateUtil.createCsr(clientKeyPair, clientSubjectDN);
        writeCertificationRequest(clientCsr, directory.resolve("client.csr"));

        X509Certificate clientCertificate = ca.issueCertificate(clientCsr, ZonedDateTime.now());
        KeyStore clientKeyStore = createKeyStore(clientKeyPair.getPrivate(), null, clientCertificate);
        storeKeyStore(clientKeyStore, directory.resolve("client.p12"), "");
        clientKeyStore = loadKeyStore(directory.resolve("client.p12"), "");
        SSLContext clientSslContext = createSslContext(clientKeyStore, null, List.of(caCertificate));

        TestServer server = new TestServer();
        server.setHttpsConfiguration(httpsAddress, createSslContext(serverKeyStore, null, List.of(caCertificate)));
        server.start();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(server.getURL(), "/demo/test").openConnection();
        connection.setSSLSocketFactory(clientSslContext.getSocketFactory());

        assertThat(connection.getResponseCode()).isEqualTo(200);
        assertThat(connection.getInputStream()).hasContent("Hello " + clientSubjectDN);
    }

    private X509Certificate firstCertificate(Certificate[] serverCertificates) {
        assertThat(serverCertificates).isNotEmpty();
        return (X509Certificate) serverCertificates[0];
    }

}
