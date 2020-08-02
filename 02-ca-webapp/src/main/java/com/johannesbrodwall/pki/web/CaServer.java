package com.johannesbrodwall.pki.web;

import com.johannesbrodwall.pki.sockets.SingleKeyStore;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.net.ssl.SSLContext;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.List;
import java.util.Properties;

public class CaServer {
    private final Server server = new Server();
    private final WebAppContext context = new WebAppContext(Resource.newClassPathResource("webapp"), "/ca-web");
    private final ServerConnector connector = new ServerConnector(server);
    private final ServerConnector secureConnector = new ServerConnector(server);
    private final SingleKeyStore keyStore;

    public CaServer(Properties properties) throws GeneralSecurityException, IOException {
        keyStore = new SingleKeyStore(properties, "server");
    }

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader("local-sockets.properties")) {
            properties.load(reader);
        }

        SingleKeyStore caKeyStore = new SingleKeyStore(properties, "ca");
        caKeyStore.exportCertificate();

        new CaServer(properties).start();
    }

    private void start() throws Exception {
        server.setHandler(context);
        server.start();

        setHttpPort(10080);
        setHttpsPort(10443, "demo-server.local", createSslContext(keyStore));
    }

    private void setHttpsPort(int port, String host, SSLContext sslContext) throws Exception {
        secureConnector.stop();
        secureConnector.setDefaultProtocol(null);
        secureConnector.setConnectionFactories(List.of(
                createSslConnectionFactory(sslContext), new HttpConnectionFactory()
        ));
        secureConnector.setHost(host);
        secureConnector.setPort(port);
        secureConnector.start();
    }

    private void setHttpPort(int port) throws Exception {
        connector.stop();
        connector.setPort(port);
        connector.start();
    }

    private SSLContext createSslContext(SingleKeyStore keyStore) throws NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, KeyStoreException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyStore.getKeyManagers(), null, null);
        return sslContext;
    }

    private SslConnectionFactory createSslConnectionFactory(SSLContext sslContext) {
        SslContextFactory.Server sslConnectionFactory = new SslContextFactory.Server();
        sslConnectionFactory.setSslContext(sslContext);
        return new SslConnectionFactory(sslConnectionFactory, "HTTP/1.1");
    }
}
