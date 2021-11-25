package com.johannesbrodwall.pki.sockets;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

public interface CertificateAuthority {
    X509Certificate getCertificate() throws KeyStoreException;

    void createCaCertificate(String issuer, ZonedDateTime validFrom) throws IOException, GeneralSecurityException;

    Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException;

    Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException;
}
