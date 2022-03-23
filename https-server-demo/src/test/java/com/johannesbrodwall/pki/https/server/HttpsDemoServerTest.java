package com.johannesbrodwall.pki.https.server;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.util.SslUtil;
import com.johannesbrodwall.pki.util.SunCertificateUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
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

class HttpsDemoServerTest {

    private KeyPairGenerator generator;
    private final String org = "JohannesCorp " + UUID.randomUUID();

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
    }

    @Test
    void shouldEchoClientCertificate() throws Exception {
        InetSocketAddress httpsAddress = new InetSocketAddress("app.boosterconf.local", 0);

        Path directory = Path.of("src/test/resources/certificates/");
        X509Certificate caCertificate = readCertificate(directory.resolve("ca.crt"));

        KeyStore serverKeyStore = loadKeyStore(directory.resolve("server.p12"), "");
        X509Certificate serverCertificate = (X509Certificate) serverKeyStore.getCertificate(serverKeyStore.aliases().nextElement());
        SSLContext serverSslContext = createSslContext(serverKeyStore, null, List.of(caCertificate));

        KeyStore clientKeyStore = loadKeyStore(directory.resolve("client.p12"), "");
        X509Certificate clientCertificate = (X509Certificate) clientKeyStore.getCertificate(clientKeyStore.aliases().nextElement());
        SSLContext clientSslContext = createSslContext(clientKeyStore, null, List.of(caCertificate));

        HttpsDemoServer server = new HttpsDemoServer();
        server.setHttpsConfiguration(httpsAddress, serverSslContext);
        server.start();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(server.getURL(), "/demo/echo").openConnection();
        connection.setSSLSocketFactory(clientSslContext.getSocketFactory());

        assertThat(connection.getResponseCode()).isEqualTo(200);
        assertThat(firstCertificate(connection.getServerCertificates()).getSubjectDN())
                .isEqualTo(serverCertificate.getSubjectDN());
        assertThat(connection.getInputStream()).hasContent("Client certificate " + clientCertificate.getSubjectDN());
    }

    @Test
    void shouldGenerate() throws Exception {
        Path directory = Path.of("target/test-data/certificates/");

        CertificateAuthority ca = new SunCertificateAuthority(Period.ofDays(10), generator.generateKeyPair(), "CN=Johannes CA, O=" + org, ZonedDateTime.now());
        SslUtil.storeKeyStore(ca.getKeyStore(), directory.resolve("ca.p12"), "");
        ca = new SunCertificateAuthority(loadKeyStore(directory.resolve("ca.p12"), ""), Period.ofDays(1));

        String clientSubjectDN = "CN=Booster Demo Cert" + UUID.randomUUID() + ", OU=dev, O=" + org;
        InetSocketAddress httpsAddress = new InetSocketAddress("app.boosterconf.local", 0);

        X509Certificate caCertificate = ca.getCaCertificate();
        writeCertificate(caCertificate, directory.resolve("ca.crt"));
        caCertificate = readCertificate(directory.resolve("ca.crt"));

        KeyPair serverKeyPair = generator.generateKeyPair();
        String serverSubjectDN = "CN=" + httpsAddress.getHostName() + ",O=" + org;

        byte[] serverCsr = createHostnameCsr(httpsAddress, serverKeyPair, serverSubjectDN);
        writeCertificationRequest(serverCsr, directory.resolve("server.csr"));

        X509Certificate serverCertificate = ca.issueCertificate(serverCsr, ZonedDateTime.now());
        assertThat(serverCertificate.getSubjectAlternativeNames()).containsOnly(List.of(2, httpsAddress.getHostName()));
        KeyStore serverKeyStore = createKeyStore(serverKeyPair.getPrivate(), null, serverCertificate);
        storeKeyStore(serverKeyStore, directory.resolve("server.p12"), "");
        serverKeyStore = loadKeyStore(directory.resolve("server.p12"), "");

        KeyPair clientKeyPair = generator.generateKeyPair();
        byte[] clientCsr = createCsr(clientSubjectDN, clientKeyPair);
        writeCertificationRequest(clientCsr, directory.resolve("client.csr"));

        X509Certificate clientCertificate = ca.issueCertificate(clientCsr, ZonedDateTime.now());
        KeyStore clientKeyStore = createKeyStore(clientKeyPair.getPrivate(), null, clientCertificate);
        storeKeyStore(clientKeyStore, directory.resolve("client.p12"), "");
        clientKeyStore = loadKeyStore(directory.resolve("client.p12"), "");
        SSLContext clientSslContext = createSslContext(clientKeyStore, null, List.of(caCertificate));

        HttpsDemoServer server = new HttpsDemoServer();
        server.setHttpsConfiguration(httpsAddress, createSslContext(serverKeyStore, null, List.of(caCertificate)));
        server.start();

        HttpsURLConnection connection = (HttpsURLConnection) new URL(server.getURL(), "/echo").openConnection();
        connection.setSSLSocketFactory(clientSslContext.getSocketFactory());

        assertThat(connection.getResponseCode()).isEqualTo(200);
        assertThat(connection.getInputStream()).hasContent("Client certificate " + clientSubjectDN);
    }

    private byte[] createCsr(String clientSubjectDN, KeyPair clientKeyPair) throws GeneralSecurityException, IOException {
//        return new CertificationRequestInfo()
//                .publicKey(clientKeyPair.getPublic())
//                .subject(new X500Name(clientSubjectDN))
//                .signWithKey(clientKeyPair.getPrivate()).toDer().toByteArray();
        return SunCertificateUtil.createCsr(clientKeyPair, clientSubjectDN);
    }

    private byte[] createHostnameCsr(InetSocketAddress httpsAddress, KeyPair serverKeyPair, String serverSubjectDN) throws GeneralSecurityException, IOException {
//        return new CertificationRequestInfo()
//                .publicKey(serverKeyPair.getPublic())
//                .subject(new X500Name(serverSubjectDN))
//                .addExtension(new Extension.SANExtensionType().dnsName(httpsAddress.getHostName()))
//                .signWithKey(serverKeyPair.getPrivate()).toDer().toByteArray();
        return SunCertificateUtil.createHostnameCsr(serverKeyPair, serverSubjectDN, httpsAddress.getHostName());
    }

    private X509Certificate firstCertificate(Certificate[] serverCertificates) {
        assertThat(serverCertificates).isNotEmpty();
        return (X509Certificate) serverCertificates[0];
    }

}
