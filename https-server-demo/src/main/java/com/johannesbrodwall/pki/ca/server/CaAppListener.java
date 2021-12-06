package com.johannesbrodwall.pki.ca.server;

import com.johannesbrodwall.pki.ca.CertificateAuthority;
import com.johannesbrodwall.pki.https.server.EchoServlet;
import org.actioncontroller.servlet.ApiServlet;

import javax.servlet.DispatcherType;
import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletRegistration;
import java.util.EnumSet;
import java.util.Map;

public class CaAppListener implements ServletContextListener {

    private final CertificateAuthorityController caController = new CertificateAuthorityController();
    private final OpenIdAuthenticationFilter authenticationFilter = new OpenIdAuthenticationFilter();

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext context = sce.getServletContext();
        context.addServlet("userinfo", new EchoServlet()).addMapping("/userInfo");

        ServletRegistration.Dynamic caRegistration = context.addServlet("ca", new ApiServlet(caController));
        caRegistration.addMapping("/ca/*");
        caRegistration.setMultipartConfig(new MultipartConfigElement(""));

        context.addFilter("authentication", authenticationFilter)
                .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "*");
    }

    public void setCertificateAuthority(CertificateAuthority certificateAuthority) {
        caController.setCertificateAuthority(certificateAuthority);
    }

    public void setAuthentication(Map<String, String> config) {
        authenticationFilter.setConfig(config);
    }
}
