package com.johannesbrodwall.pki.web;

import com.johannesbrodwall.pki.sockets.KeyStoreFile;
import org.eclipse.jetty.server.AbstractConnectionFactory;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.net.ssl.SSLContext;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;

public class CaServer {
    private final Server server = new Server();
    private final WebAppContext context = new CaWebApp("/ca-web");

    private final ServerConnector connector = new ServerConnector(server);
    private ServerConnector secureConnector = new ServerConnector(server);
    private final KeyStoreFile keyStore;

    public CaServer(Properties properties) throws GeneralSecurityException, IOException {
        keyStore = new KeyStoreFile(properties, "server", null);
    }

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        try (FileReader reader = new FileReader("local-sockets.properties")) {
            properties.load(reader);
        }

        KeyStoreFile caKeyStore = new KeyStoreFile(properties, "ca", null);
        caKeyStore.getKeyStore().exportCertificate();

        new CaServer(properties).start();
    }

    private void start() throws Exception {
        server.setHandler(context);
        server.start();

        setHttpPort(10080);
        setHttpsPort(10443, "ca-server.local", keyStore.createSslContext());
    }

    private void setHttpsPort(int port, String host, SSLContext sslContext) throws Exception {
        secureConnector.stop();
        secureConnector.setDefaultProtocol(null);
        secureConnector.setConnectionFactories(List.of(AbstractConnectionFactory.getFactories(
                createSslConnectionFactory(sslContext), new HttpConnectionFactory()
        )));
        secureConnector.setHost(host);
        secureConnector.setPort(port);
        secureConnector.start();
    }

    private void setHttpPort(int port) throws Exception {
        connector.stop();
        connector.setPort(port);
        connector.start();
    }

    private SslContextFactory.Server createSslConnectionFactory(SSLContext sslContext) {
        SslContextFactory.Server sslConnectionFactory = new SslContextFactory.Server();
        sslConnectionFactory.setSslContext(sslContext);
        return sslConnectionFactory;
    }
}
