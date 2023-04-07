package com.johannesbrodwall.pki.https.server;

import com.johannesbrodwall.pki.infrastructure.SslServerConnector;
import com.johannesbrodwall.pki.util.SslUtil;
import com.johannesbrodwall.pki.util.SunCertificateUtil;
import org.actioncontroller.config.ConfigMap;
import org.actioncontroller.config.ConfigObserver;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Optional;

import static com.johannesbrodwall.pki.util.SslUtil.createKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.createSslContext;
import static com.johannesbrodwall.pki.util.SslUtil.readCertificate;
import static com.johannesbrodwall.pki.util.SslUtil.readCertificates;
import static com.johannesbrodwall.pki.util.SslUtil.readPrivateKey;
import static com.johannesbrodwall.pki.util.SslUtil.writePrivateKey;

public class HttpsDemoServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpsDemoServer.class);

    private final Server server = new Server();
    private final SslServerConnector secureConnector = new SslServerConnector(server);
    private final ServerConnector connector = new ServerConnector(server);

    public static void main(String[] args) throws Exception {
        HttpsDemoServer server = new HttpsDemoServer();
        new ConfigObserver("pkidemo")
                .onInetSocketAddress("http.address", 8080, server::setHttpAddress)
                .onPrefixedValue("https", server::setHttpsConfiguration);
        server.start();
    }

    private void setHttpAddress(InetSocketAddress httpAddress) throws Exception {
        connector.stop();
        connector.setHost(httpAddress.getHostName());
        connector.setPort(httpAddress.getPort());
        connector.start();
        logger.info("Started http://{}:{}", connector.getHost(), connector.getPort());
    }

    private void setHttpsConfiguration(ConfigMap config) throws Exception {
        secureConnector.stop();
        Optional<Path> keyFile = config.optionalFile("key");
        Optional<Path> certificate = config.optionalFile("certificate");
        InetSocketAddress address = config.getInetSocketAddress("address", 8443);

        if (keyFile.isPresent() && certificate.isPresent()) {
            secureConnector.start(
                    address,
                    createSslContext(
                            createKeyStore(readPrivateKey(keyFile.get()), null, readCertificate(certificate.get())),
                            config.get("password").toCharArray(),
                            readCertificates(config.listFiles("trustedCertificates"))
                    ),
                    config.getBoolean("wantClientAuth"),
                    config.getBoolean("needClientAuth")
            );
        } else if (keyFile.isEmpty()) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            writePrivateKey(keyPair.getPrivate(), Path.of(config.get("key")));
            SslUtil.writeCertificationRequest(
                    SunCertificateUtil.createHostnameCsr(keyPair, "CN=" + address.getHostName(), address.getHostName()),
                    Path.of(config.get("key") + ".csr")
            );
        }
    }

    public void setHttpsConfiguration(InetSocketAddress address, SSLContext sslContext) throws Exception {
        secureConnector.start(address, sslContext, true, false);
    }

    public void start() throws Exception {
        ServletContextHandler handler = new ServletContextHandler();
        handler.setContextPath("/");
        handler.addServlet(new ServletHolder(new EchoServlet()), "/*");
        server.setHandler(handler);
        server.addConnector(secureConnector);
        server.addConnector(connector);
        server.start();
    }

    public URL getURL() throws MalformedURLException {
        return server.getURI().toURL();
    }
}
