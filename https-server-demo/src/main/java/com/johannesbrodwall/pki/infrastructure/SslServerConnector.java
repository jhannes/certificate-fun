package com.johannesbrodwall.pki.infrastructure;

import org.eclipse.jetty.server.AbstractConnectionFactory;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.List;

public class SslServerConnector extends ServerConnector {

    private static final Logger logger = LoggerFactory.getLogger(SslServerConnector.class);

    public SslServerConnector(Server server) {
        super(server);
    }

    public void start(InetSocketAddress address, SSLContext sslContext, boolean wantClientAuth, boolean needClientAuth) throws Exception {
        setPort(address.getPort());
        setHost(address.getHostName());
        setDefaultProtocol(null);
        setConnectionFactories(createConnectionFactories(sslContext, wantClientAuth, needClientAuth));
        start();

        logger.info("Started https://{}:{}", address.getHostName(), address.getPort());
    }

    private Collection<ConnectionFactory> createConnectionFactories(SSLContext sslContext, boolean wantClientAuth, boolean needClientAuth) {
        SslContextFactory.Server sslConnectionFactory = new SslContextFactory.Server();
        sslConnectionFactory.setSslContext(sslContext);
        sslConnectionFactory.setWantClientAuth(wantClientAuth);
        sslConnectionFactory.setNeedClientAuth(needClientAuth);
        return List.of(AbstractConnectionFactory.getFactories(sslConnectionFactory, new HttpConnectionFactory()));
    }

}
