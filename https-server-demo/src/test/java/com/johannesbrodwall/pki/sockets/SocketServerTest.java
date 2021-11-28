package com.johannesbrodwall.pki.sockets;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.util.SslUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SocketServerTest {

    private KeyPairGenerator generator;
    private CertificateAuthority certificateAuthority;
    private final ZonedDateTime now = ZonedDateTime.now();
    private KeyManager[] serverKeyManagers;
    private TrustManager[] caTrustManagers;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException {
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        certificateAuthority = new SunCertificateAuthority(Period.ofDays(1), generator.generateKeyPair(), "CN=Test Root CA,O=Certificate Fun Corp", now);
        caTrustManagers = SslUtil.createTrustManagers(List.of(certificateAuthority.getCaCertificate()));

        KeyPair serverKeyPair = generator.generateKeyPair();
        X509Certificate serverCertificate = certificateAuthority.issueServerCertificate("localhost", "CN=localhost,O=Server Org", now, serverKeyPair.getPublic());
        serverKeyManagers = SslUtil.createKeyManagers(serverKeyPair, serverCertificate);
    }
    @Test
    void serverShouldEchoClientSubjectDN() throws GeneralSecurityException, IOException {
        SocketServer server = new SocketServer(SslUtil.createSslContext(serverKeyManagers, caTrustManagers));
        new Thread(server::run).start();

        KeyPair clientKeyPair = generator.generateKeyPair();
        X509Certificate clientCertificate = certificateAuthority.issueClientCertificate("CN=Client,O=Client Org", now, clientKeyPair.getPublic());
        KeyManager[] clientKeyManagers = SslUtil.createKeyManagers(clientKeyPair, clientCertificate);

        SocketClient client = new SocketClient(SslUtil.createSslContext(clientKeyManagers, caTrustManagers));
        String response = client.run(InetSocketAddress.createUnresolved("localhost", server.getPort()));
        assertThat(response).isEqualTo("Hello " + clientCertificate.getSubjectDN());
    }

    @Test
    void serverAcceptUnauthorizedClients() throws GeneralSecurityException, IOException {
        SocketServer server = new SocketServer(SslUtil.createSslContext(serverKeyManagers, caTrustManagers));
        new Thread(server::run).start();

        SocketClient client = new SocketClient(SslUtil.createSslContext(null, caTrustManagers));
        String response = client.run(InetSocketAddress.createUnresolved("localhost", server.getPort()));
        assertThat(response).isEqualTo("Hello stranger");
    }
}
