package com.johannesbrodwall.pki.sockets;

import io.liquidpki.common.CertificateExtensions;
import io.liquidpki.common.Extension;
import io.liquidpki.common.X501Name;
import io.liquidpki.x509.X509Certificate.TbsCertificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Period;
import java.time.ZonedDateTime;

public class LiquidPkiCertificateAuthority implements CertificateAuthority {

    private final Period validity;

    private final SingleKeyStore keyStore;

    public LiquidPkiCertificateAuthority(KeyStoreFile keyStoreFile, Period validity) {
        this(keyStoreFile.getKeyStore(), validity);
    }

    public LiquidPkiCertificateAuthority(SingleKeyStore keyStore, Period validity) {
        this.keyStore = keyStore;
        this.validity = validity;
    }

    @Override
    public X509Certificate getCertificate() throws KeyStoreException {
        return keyStore.getCertificate();
    }

    @Override
    public void createCaCertificate(String issuer, ZonedDateTime validFrom) throws GeneralSecurityException {
        KeyPair keyPair = keyStore.generateKeyPair();

        keyStore.setEntry(keyPair.getPrivate(), toX509Certificate(new io.liquidpki.x509.X509Certificate()
                .tbsCertificate(new TbsCertificate()
                        .version(2)
                        .validity(validFrom, validFrom.plus(validity))
                        .serialNumber(new SecureRandom().nextLong())
                        .publicKey((RSAPublicKey) keyPair.getPublic())
                        .subjectName(new X501Name(issuer))
                        .issuerName(new X501Name(issuer))
                        .addExtension(new Extension.BasicConstraintExtensionType().ca(true))
                        .addExtension(new CertificateExtensions().keyUsage().keyCertSign(true).crlSign(true))
                )
                .signWithKey(keyPair.getPrivate(), "SHA512withRSA")));
    }

    @Override
    public Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws GeneralSecurityException {
        return toX509Certificate(new io.liquidpki.x509.X509Certificate()
                .tbsCertificate(new TbsCertificate()
                        .version(2)
                        .validity(validFrom, validFrom.plus(validity))
                        .serialNumber(new SecureRandom().nextLong())
                        .publicKey((RSAPublicKey) publicKey)
                        .subjectName(new X501Name(subject))
                        .issuerName(new X501Name(getSubjectDN()))
                        .addExtension(new CertificateExtensions()
                            .sanExtension().dnsName(hostname)
                        )
                )
                .signWithKey(getPrivateKey(), "SHA512withRSA"));
    }

    @Override
    public Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws GeneralSecurityException {
        return toX509Certificate(new io.liquidpki.x509.X509Certificate()
                .tbsCertificate(new TbsCertificate()
                        .version(2)
                        .validity(validFrom, validFrom.plus(validity))
                        .serialNumber(new SecureRandom().nextLong())
                        .publicKey((RSAPublicKey) publicKey)
                        .subjectName(new X501Name(subject))
                        .issuerName(new X501Name(getSubjectDN()))
                )
                .signWithKey(getPrivateKey(), "SHA512withRSA"));
    }

    private PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return keyStore.getPrivateKey();
    }

    private String getSubjectDN() throws KeyStoreException {
        return keyStore.getSubjectDN();
    }

    private Certificate toX509Certificate(io.liquidpki.x509.X509Certificate certificate) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return certFactory.generateCertificate(new ByteArrayInputStream(certificate.toDer().toByteArray()));
    }

}
