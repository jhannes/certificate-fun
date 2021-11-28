package com.johannesbrodwall.pki.ca;

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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.List;

public class SunCertificateAuthority implements CertificateAuthority {

    private final Period validity;
    private final KeyPair caKeyPair;
    private final X509Certificate caCertificate;

    public SunCertificateAuthority(Period validity, KeyPair caKeyPair, String issuer, ZonedDateTime validFrom) throws IOException, GeneralSecurityException {
        this.validity = validity;
        this.caKeyPair = caKeyPair;

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        this.caCertificate = sign(SunCertificateUtil.createX509Cert(new X500Name(issuer), new X500Name(issuer), validFrom, validFrom.plus(validity), extensions, caKeyPair.getPublic()));
    }

    @Override
    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    @Override
    public X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException {
        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set(
                SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(SunCertificateUtil.createGeneralNames(List.of(new GeneralName(new DNSName(hostname)))))
        );
        return sign(SunCertificateUtil.createX509Cert(new X500Name(subject), getIssuer(), validFrom, validFrom.plus(validity), extensions, publicKey));
    }

    @Override
    public X509Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws GeneralSecurityException, IOException {
        return sign(SunCertificateUtil.createX509Cert(new X500Name(subject), getIssuer(), validFrom, validFrom.plus(validity), null, publicKey));
    }

    @Override
    public X509Certificate issueCertificate(byte[] certificationRequest, ZonedDateTime validFrom) throws IOException, GeneralSecurityException {
        PKCS10 pkcs10 = new PKCS10(certificationRequest);
        return sign(SunCertificateUtil.createX509Cert(
                pkcs10.getSubjectName(),
                getIssuer(),
                validFrom,
                validFrom.plus(validity),
                SunCertificateUtil.getCertificateExtensions(pkcs10),
                pkcs10.getSubjectPublicKeyInfo())
        );
    }

    private X509CertImpl sign(X509CertImpl x509Cert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        x509Cert.sign(getPrivateKey(), "SHA512withRSA");
        return x509Cert;
    }

    private PrivateKey getPrivateKey() {
        return caKeyPair.getPrivate();
    }

    private X500Name getIssuer() throws IOException {
        return new X500Name(caCertificate.getSubjectDN().toString());
    }
}
