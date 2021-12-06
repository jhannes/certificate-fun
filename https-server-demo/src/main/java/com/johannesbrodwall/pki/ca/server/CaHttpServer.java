package com.johannesbrodwall.pki.ca.server;

import com.johannesbrodwall.pki.ca.SunCertificateAuthority;
import com.johannesbrodwall.pki.infrastructure.SslServerConnector;
import com.johannesbrodwall.pki.util.SslUtil;
import com.johannesbrodwall.pki.infrastructure.WebApplication;
import org.actioncontroller.config.ConfigMap;
import org.actioncontroller.config.ConfigObserver;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.MovedContextHandler;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

import static com.johannesbrodwall.pki.util.SslUtil.createKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.loadKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.storeKeyStore;
import static com.johannesbrodwall.pki.util.SslUtil.writeCertificate;

public class CaHttpServer {

    private final Server server = new Server();
    private final SslServerConnector secureConnector = new SslServerConnector(server);
    private final CaAppListener caApplication = new CaAppListener();
    private final WebAppContext application = new WebApplication("/webapp", "/ca", caApplication);

    public static void main(String[] args) throws Exception {
        CaHttpServer server = new CaHttpServer();
        new ConfigObserver("pkidemo")
                .onPrefixedValue("ca.authentication", server::setAuthentication)
                .onPrefixedValue("ca", server::setCaConfiguration);

        server.start();
    }

    private void setAuthentication(ConfigMap config) {
        caApplication.setAuthentication(config);
    }

    private void setCaConfiguration(ConfigMap config) throws Exception {
        Optional<Path> keystore = config.optionalFile("keystore");
        if (keystore.isPresent() && !config.getBoolean("create.ifPresent")) {
            setCertificateAuthority(loadCertificateAuthority(config, keystore.get()), config);
        } else if (config.containsKey("keystore") && config.getBoolean("create.ifMissing")) {
            setCertificateAuthority(createCertificateAuthority(config), config);
        } else {
            throw new IllegalArgumentException("Missing keystore");
        }
    }

    private SunCertificateAuthority createCertificateAuthority(ConfigMap config) throws IOException, GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        SunCertificateAuthority certificateAuthority = new SunCertificateAuthority(
                config.optional("validityPeriod").map(Period::parse).orElse(Period.ofDays(1)),
                generator.generateKeyPair(),
                config.get("create.issuerDN"),
                ZonedDateTime.now()
        );
        Path keystore = Path.of(config.get("keystore"));
        if (keystore.getParent() != null) {
            Files.createDirectories(keystore.getParent());
        }
        storeKeyStore(certificateAuthority.getKeyStore(), keystore, config.getOrDefault("keystorePassword", ""));
        writeCertificate(certificateAuthority.getCaCertificate(), Path.of(stripExtension(keystore.toString()) + ".crt"));
        return certificateAuthority;
    }

    private String stripExtension(String path) {
        int lastPeriod = path.lastIndexOf('.');
        return lastPeriod > 0 ? path.substring(0, lastPeriod) : path;
    }

    private SunCertificateAuthority loadCertificateAuthority(ConfigMap config, Path keyStoreFile) throws GeneralSecurityException, IOException {
        return new SunCertificateAuthority(
                loadKeyStore(keyStoreFile, config.getOrDefault("keystorePassword", "")),
                config.optional("validityPeriod").map(Period::parse).orElse(Period.ofDays(1))
        );
    }

    private void setCertificateAuthority(SunCertificateAuthority certificateAuthority, ConfigMap config) throws Exception {
        secureConnector.stop();

        caApplication.setCertificateAuthority(certificateAuthority);
        InetSocketAddress address = config.getInetSocketAddress("https.address", 10443);

        secureConnector.start(
                address,
                createSslContext(address, certificateAuthority),
                config.getBoolean("wantClientAuth"),
                config.getBoolean("needClientAuth")
        );
    }

    private SSLContext createSslContext(InetSocketAddress address, SunCertificateAuthority certificateAuthority) throws GeneralSecurityException, IOException, InvalidNameException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = generator.generateKeyPair();

        X509Certificate caCertificate = certificateAuthority.getCaCertificate();
        LdapName subjectName = new LdapName(certificateAuthority.getCaCertificate().getIssuerDN().toString());
        replace(subjectName, "CN", address.getHostName());
        KeyStore keyStore = createKeyStore(
                keyPair.getPrivate(),
                null,
                certificateAuthority.issueServerCertificate(address.getHostName(), subjectName.toString(), ZonedDateTime.now(), keyPair.getPublic())
        );
        return SslUtil.createSslContext(keyStore, null, List.of(caCertificate));
    }

    private void replace(LdapName subjectName, String attribute, String value) throws InvalidNameException {
        for (int i = subjectName.size() - 1; i >= 0; i--) {
            if (subjectName.getRdn(i).getType().equals(attribute)) {
                subjectName.remove(i);
            }
        }
        subjectName.add(attribute + "=" + value);
    }


    private void start() throws Exception {
        server.setHandler(new HandlerList(
                application,
                new MovedContextHandler(null, "/", application.getContextPath())
        ));
        server.addConnector(secureConnector);
        server.start();
    }
}
