package com.johannesbrodwall.pki.server;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class DemoAppListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        sce.getServletContext().addServlet("hello", new HelloServlet()).addMapping("/test");
    }
}
