package com.johannesbrodwall.pki.server;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.X509Certificate;

public class HelloServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        X509Certificate[] clientCertificate = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
        if (clientCertificate != null && clientCertificate.length > 0) {
            resp.getWriter().write("Hello " + clientCertificate[0].getSubjectDN());
        } else {
            resp.getWriter().write("Hello there");
        }
    }
}
