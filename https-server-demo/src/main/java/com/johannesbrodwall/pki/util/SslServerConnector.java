package com.johannesbrodwall.pki.util;

import org.eclipse.jetty.server.AbstractConnectionFactory;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.List;

public class SslServerConnector extends ServerConnector {
    public SslServerConnector(Server server) {
        super(server);
    }

    public void start(InetSocketAddress address, SSLContext sslContext, boolean wantClientAuth, boolean needClientAuth) throws Exception {
        setPort(address.getPort());
        setHost(address.getHostName());
        setDefaultProtocol(null);
        setConnectionFactories(createConnectionFactories(sslContext, wantClientAuth, needClientAuth));
        start();
    }

    private Collection<ConnectionFactory> createConnectionFactories(SSLContext sslContext, boolean wantClientAuth, boolean needClientAuth) {
        SslContextFactory.Server sslConnectionFactory = new SslContextFactory.Server();
        sslConnectionFactory.setSslContext(sslContext);
        sslConnectionFactory.setWantClientAuth(wantClientAuth);
        sslConnectionFactory.setNeedClientAuth(needClientAuth);
        return List.of(AbstractConnectionFactory.getFactories(sslConnectionFactory, new HttpConnectionFactory()));
    }

}
