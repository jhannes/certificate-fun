package com.johannesbrodwall.pki.sockets;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.util.SslUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SocketServerTest {

    private KeyPairGenerator generator;
    private CertificateAuthority certificateAuthority;
    private final ZonedDateTime now = ZonedDateTime.now();

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        certificateAuthority = new SunCertificateAuthority(Period.ofDays(1), generator.generateKeyPair(), "CN=Test Root CA,O=Certificate Fun Corp", now);
    }

    @Test
    void serverShouldEchoClientSubjectDN() throws GeneralSecurityException, IOException {
        KeyPair serverKeyPair = generator.generateKeyPair();
        X509Certificate serverCertificate = certificateAuthority.issueServerCertificate("localhost", "CN=localhost,O=Server Org", now, serverKeyPair.getPublic());

        KeyPair clientKeyPair = generator.generateKeyPair();
        X509Certificate clientCertificate = certificateAuthority.issueClientCertificate("CN=Client,O=Client Org", now, clientKeyPair.getPublic());

        SocketServer server = new SocketServer(SslUtil.createSslContext(
                SslUtil.createKeyStore(serverKeyPair.getPrivate(), null, serverCertificate),
                null,
                List.of(certificateAuthority.getCaCertificate())
        ));
        new Thread(server::run).start();

        SocketClient client = new SocketClient(SslUtil.createSslContext(
                SslUtil.createKeyStore(clientKeyPair.getPrivate(), null, clientCertificate),
                null,
                List.of(certificateAuthority.getCaCertificate())
        ));
        String response = client.run(InetSocketAddress.createUnresolved("localhost", server.getPort()));
        assertThat(response).isEqualTo("Hello " + clientCertificate.getSubjectDN());
    }
}
