package com.johannesbrodwall.pki.ca;

import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Date;

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

        this.caCertificate = createSignedCertificate(issuer, issuer, validFrom, validFrom.plus(validity), extensions, caKeyPair.getPublic());
    }

    @Override
    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    @Override
    public X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, GeneralSecurityException {
        CertificateExtensions extensions = new CertificateExtensions();
        GeneralNames subjectAlternativeNames = new GeneralNames();
        subjectAlternativeNames.add(new GeneralName(new DNSName(hostname)));
        extensions.set(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension(subjectAlternativeNames));

        return createSignedCertificate(subject, getSubjectDN(), validFrom, validFrom.plus(validity), extensions, publicKey);
    }

    @Override
    public X509Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws GeneralSecurityException, IOException {
        return createSignedCertificate(subject, getSubjectDN(), validFrom, validFrom.plus(validity), null, publicKey);
    }

    private X509CertImpl createSignedCertificate(
            String subject,
            String issuer,
            ZonedDateTime validFrom,
            ZonedDateTime validTo,
            CertificateExtensions extensions,
            PublicKey publicKey
    ) throws GeneralSecurityException, IOException {
        X509CertInfo certInfo = new X509CertInfo();
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant())
        ));
        certInfo.set(X509CertInfo.SERIAL_NUMBER,
                new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid)));
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(subject));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(issuer));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        if (extensions != null) {
            certInfo.set(X509CertInfo.EXTENSIONS, extensions);
        }

        X509CertImpl x509Cert = new X509CertImpl(certInfo);
        x509Cert.sign(getPrivateKey(), "SHA512withRSA");
        return x509Cert;
    }

    private PrivateKey getPrivateKey() {
        return caKeyPair.getPrivate();
    }

    private String getSubjectDN() {
        return caCertificate.getSubjectDN().toString();
    }

}
