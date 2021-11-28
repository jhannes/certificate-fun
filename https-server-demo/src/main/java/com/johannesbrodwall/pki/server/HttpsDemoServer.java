package com.johannesbrodwall.pki.server;

import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.util.SslServerConnector;
import com.johannesbrodwall.pki.util.WebApplication;
import org.actioncontroller.config.ConfigMap;
import org.actioncontroller.config.ConfigObserver;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Optional;

import static com.johannesbrodwall.pki.util.SslUtil.loadKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.storeKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.toSslContext;

public class HttpsDemoServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpsDemoServer.class);

    private final Server server = new Server();
    private final SslServerConnector secureConnector = new SslServerConnector(server);
    private final CertificateAuthorityController caController = new CertificateAuthorityController();
    private final WebAppContext application = new WebApplication("/webapp", "/demo", new DemoAppListener(caController));

    public static void main(String[] args) throws Exception {
        HttpsDemoServer server = new HttpsDemoServer();
        new ConfigObserver("pkidemo")
                .onPrefixedValue("ca", server::setCaConfiguration)
                .onPrefixedValue("https", server::setHttpsConfiguration);
        server.start();
        logger.info("Started {}", server.getURL());
        Thread.sleep(1000000000);
    }

    private void setCaConfiguration(ConfigMap config) throws GeneralSecurityException, IOException {
        Optional<Path> keystore = config.optionalFile("keystore");
        if (keystore.isPresent() && !config.getBoolean("create.ifPresent")) {
            caController.setCertificateAuthority(new SunCertificateAuthority(
                    loadKeyStore(keystore.get(), config.getOrDefault("keystorePassword", "")),
                    config.optional("validityPeriod").map(Period::parse).orElse(Period.ofDays(1))
            ));
        } else if (config.containsKey("keystore") && config.getBoolean("create.ifMissing")) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            SunCertificateAuthority certificateAuthority = new SunCertificateAuthority(
                    config.optional("validityPeriod").map(Period::parse).orElse(Period.ofDays(1)),
                    generator.generateKeyPair(),
                    config.get("create.issuerDN"),
                    ZonedDateTime.now()
            );
            storeKeyStore(certificateAuthority.getKeyStore(), Path.of(config.get("keystore")), config.getOrDefault("keystorePassword", ""));
            caController.setCertificateAuthority(certificateAuthority);
        } else {
            throw new IllegalArgumentException("Missing keystore");
        }
    }

    private void setHttpsConfiguration(ConfigMap config) throws Exception {
        secureConnector.stop();
        Optional<Path> keystore = config.optionalFile("keystore");
        if (keystore.isPresent()) {
            secureConnector.start(
                    config.getInetSocketAddress("address", 8443),
                    toSslContext(config, keystore.get(), config.listFiles("trustedCertificates")),
                    config.getBoolean("wantClientAuth"),
                    config.getBoolean("needClientAuth")
            );
        }
    }

    public void setHttpsConfiguration(InetSocketAddress localhost, SSLContext sslContext) throws Exception {
        secureConnector.start(localhost, sslContext, true, false);
    }

    public void start() throws Exception {
        server.setHandler(application);
        server.addConnector(secureConnector);
        server.start();
    }

    public URL getURL() throws MalformedURLException {
        return server.getURI().toURL();
    }
}
