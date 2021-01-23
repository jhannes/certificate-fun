package com.johannesbrodwall.pki.web;

import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;

public class CaWebApp extends WebAppContext {
    public CaWebApp(String contextPath) {
        super(Resource.newClassPathResource("webapp"), contextPath);

        addServlet(new ServletHolder(new CaServlet()), "/api/*");
    }
}
