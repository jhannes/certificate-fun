package com.johannesbrodwall.pki.sockets;

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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Date;

public class SunCertificateAuthority implements CertificateAuthority {

    private final Period validity;

    private final SingleKeyStore keyStore;

    public SunCertificateAuthority(KeyStoreFile keyStoreFile, Period validity) {
        this(keyStoreFile.getKeyStore(), validity);
    }

    public SunCertificateAuthority(SingleKeyStore keyStore, Period validity) {
        this.keyStore = keyStore;
        this.validity = validity;
    }

    @Override
    public X509Certificate getCertificate() throws KeyStoreException {
        return keyStore.getCertificate();
    }

    @Override
    public void createCaCertificate(String issuer, ZonedDateTime validFrom) throws IOException, GeneralSecurityException {
        KeyPair keyPair = keyStore.generateKeyPair();

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        X509CertImpl certificateImpl = createCertificate(issuer, issuer, validFrom, validFrom.plus(validity), extensions, keyPair.getPublic());
        certificateImpl.sign(keyPair.getPrivate(), "SHA512withRSA");

        keyStore.setEntry(keyPair.getPrivate(), certificateImpl);
    }

    @Override
    public Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, UnrecoverableKeyException {
        CertificateExtensions extensions = new CertificateExtensions();
        GeneralNames subjectAlternativeNames = new GeneralNames();
        subjectAlternativeNames.add(new GeneralName(new DNSName(hostname)));
        extensions.set(SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(subjectAlternativeNames));

        X509CertImpl serverCertificate = createCertificate(subject, getSubjectDN(), validFrom, validFrom.plus(validity), extensions, publicKey);
        serverCertificate.sign(getPrivateKey(), "SHA512withRSA");
        return serverCertificate;
    }

    @Override
    public Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException {
        X509CertImpl serverCertificate = createCertificate(subject, getSubjectDN(), validFrom, validFrom.plus(validity), null, publicKey);
        serverCertificate.sign(getPrivateKey(), "SHA512withRSA");
        return serverCertificate;
    }

    private static X509CertImpl createCertificate(String subject, String issuer, ZonedDateTime validFrom, ZonedDateTime validTo, CertificateExtensions extensions, PublicKey publicKey) throws CertificateException, IOException {
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

        return new X509CertImpl(certInfo);
    }

    private PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return keyStore.getPrivateKey();
    }

    private String getSubjectDN() throws KeyStoreException {
        return keyStore.getSubjectDN();
    }
}
