package com.johannesbrodwall.pki.server;

import org.actioncontroller.servlet.ApiServlet;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletRegistration;

public class DemoAppListener implements ServletContextListener {

    private final CertificateAuthorityController caController;

    public DemoAppListener(CertificateAuthorityController certificateAuthorityController) {
        this.caController = certificateAuthorityController;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext context = sce.getServletContext();
        context.addServlet("echo", new EchoServer()).addMapping("/echo");

        ServletRegistration.Dynamic caRegistration = context.addServlet("ca", new ApiServlet(caController));
        caRegistration.addMapping("/ca/*");
        caRegistration.setMultipartConfig(new MultipartConfigElement(""));
    }
}
