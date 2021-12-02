package com.johannesbrodwall.pki.infrastructure;

import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.servlet.ServletContextListener;

public class WebApplication extends WebAppContext {

    public WebApplication(String webapp, String contextPath, ServletContextListener applicationListener) {
        super(Resource.newClassPathResource(webapp), contextPath);
        addEventListener(applicationListener);
    }
}
