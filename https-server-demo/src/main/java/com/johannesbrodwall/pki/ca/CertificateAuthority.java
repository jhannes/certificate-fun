package com.johannesbrodwall.pki.ca;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Optional;

public interface CertificateAuthority {
    X509Certificate getCaCertificate() throws KeyStoreException;

    X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException;

    default X509Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException {
        return issueCertificate(subject, validFrom, publicKey, Optional.empty());
    }

    X509Certificate issueCertificate(String subjectName, ZonedDateTime validFrom, PublicKey publicKey, Optional<byte[]> csrForExtensions) throws IOException, GeneralSecurityException;

    X509Certificate issueCertificate(byte[] certificationRequest, ZonedDateTime validFrom) throws IOException, GeneralSecurityException;

    KeyStore getKeyStore() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException;
}
