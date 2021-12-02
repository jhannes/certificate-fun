package com.johannesbrodwall.pki.ca.server;

import com.johannesbrodwall.pki.https.server.EchoServlet;
import org.actioncontroller.servlet.ApiServlet;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletRegistration;

public class CaAppListener implements ServletContextListener {

    private final CertificateAuthorityController caController;

    public CaAppListener(CertificateAuthorityController certificateAuthorityController) {
        this.caController = certificateAuthorityController;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext context = sce.getServletContext();
        context.addServlet("echo", new EchoServlet()).addMapping("/echo");

        ServletRegistration.Dynamic caRegistration = context.addServlet("ca", new ApiServlet(caController));
        caRegistration.addMapping("/ca/*");
        caRegistration.setMultipartConfig(new MultipartConfigElement(""));
    }
}
