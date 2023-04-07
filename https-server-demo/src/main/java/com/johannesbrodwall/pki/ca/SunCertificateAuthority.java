package com.johannesbrodwall.pki.ca;

import com.johannesbrodwall.pki.util.ExceptionUtil;
import com.johannesbrodwall.pki.util.SslUtil;
import com.johannesbrodwall.pki.util.SunCertificateUtil;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

public class SunCertificateAuthority implements CertificateAuthority {

    private final Period validity;
    private final PrivateKey caPrivateKey;
    private final X509Certificate caCertificate;

    public SunCertificateAuthority(Period validity, KeyPair caKeyPair, String issuer, ZonedDateTime validFrom) throws IOException, GeneralSecurityException {
        this.validity = validity;
        caPrivateKey = caKeyPair.getPrivate();

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        X509CertImpl certificate = sign(SunCertificateUtil.createX509Cert(new X500Name(issuer), new X500Name(issuer), validFrom, validFrom.plus(validity), Optional.of(extensions), caKeyPair.getPublic()));
        this.caCertificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    public SunCertificateAuthority(KeyStore keyStore, Period validityPeriod) throws GeneralSecurityException {
        this.validity = validityPeriod;
        String alias = keyStore.aliases().nextElement();
        caPrivateKey = (PrivateKey) keyStore.getKey(alias, null);
        caCertificate = (X509Certificate) keyStore.getCertificate(alias);
    }

    @Override
    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    @Override
    public KeyStore getKeyStore() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        return SslUtil.createKeyStore(caPrivateKey, null, caCertificate);
    }

    @Override
    public X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException {
        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set(
                SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(SunCertificateUtil.createGeneralNames(List.of(
                        new GeneralName(new DNSName(hostname)),
                        new GeneralName(new DNSName("localhost")))
                ))
        );
        return doIssueCertificate(subject, validFrom, publicKey, Optional.of(extensions));
    }

    @Override
    public X509Certificate issueCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey, Optional<byte[]> extensions) throws GeneralSecurityException, IOException {
        return doIssueCertificate(subject, validFrom, publicKey, extensions.flatMap(ExceptionUtil.softenFunction(this::decodeExtensions)));
    }

    private Optional<CertificateExtensions> decodeExtensions(byte[] bytes) throws IOException, SignatureException, NoSuchAlgorithmException {
        PKCS10 pkcs10 = new PKCS10(bytes);
        return Optional.ofNullable(SunCertificateUtil.getCertificateExtensions(pkcs10));
    }

    @Override
    public X509Certificate issueCertificate(byte[] certificationRequest, ZonedDateTime validFrom) throws IOException, GeneralSecurityException {
        PKCS10 pkcs10 = new PKCS10(certificationRequest);
        Optional<CertificateExtensions> certificateExtensions = Optional.ofNullable(SunCertificateUtil.getCertificateExtensions(pkcs10));
        return doIssueCertificate(pkcs10.getSubjectName().toString(), validFrom, pkcs10.getSubjectPublicKeyInfo(), certificateExtensions);
    }

    private X509Certificate doIssueCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey, Optional<CertificateExtensions> certificateExtensions) throws GeneralSecurityException, IOException {
        return sign(SunCertificateUtil.createX509Cert(
                new X500Name(subject),
                getIssuer(),
                validFrom,
                validFrom.plus(validity),
                certificateExtensions,
                publicKey
        ));
    }

    private X509CertImpl sign(X509CertImpl x509Cert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        x509Cert.sign(caPrivateKey, "SHA512withRSA");
        return x509Cert;
    }

    private X500Name getIssuer() throws IOException {
        return new X500Name(caCertificate.getSubjectDN().toString());
    }
}
