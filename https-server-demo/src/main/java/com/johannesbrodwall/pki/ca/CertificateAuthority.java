package com.johannesbrodwall.pki.ca;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

public interface CertificateAuthority {
    X509Certificate getCaCertificate() throws KeyStoreException;

    X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException;

    X509Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException;

    X509Certificate issueCertificate(byte[] certificationRequest, ZonedDateTime validFrom) throws IOException, GeneralSecurityException;
}
