package com.johannesbrodwall.pki.util;

import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attribute;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class SunCertificateUtil {

    public static byte[] createHostnameCsr(KeyPair keyPair, String subjectDN, String hostname) throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException, SignatureException {
        return encodeAndSign(new PKCS10(keyPair.getPublic(), createHostnameAttributes(hostname)), new X500Name(subjectDN), keyPair.getPrivate());
    }

    private static PKCS10Attributes createHostnameAttributes(String hostname) throws IOException {
        CertificateExtensions extensions = new CertificateExtensions();
        extensions.set(
                SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(createGeneralNames(List.of(new GeneralName(new DNSName(hostname)))))
        );
        return new PKCS10Attributes(new PKCS10Attribute[] {
                new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, extensions)
        });
    }

    public static byte[] createCsr(KeyPair keyPair, String subjectDN) throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException, SignatureException {
        return encodeAndSign(new PKCS10(keyPair.getPublic()), new X500Name(subjectDN), keyPair.getPrivate());
    }

    private static byte[] encodeAndSign(PKCS10 pkcs10, X500Name subject, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, IOException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        pkcs10.encodeAndSign(subject, signature);
        return pkcs10.getEncoded();
    }

    public static X509CertImpl createX509Cert(
            X500Name subject,
            X500Name issuer,
            ZonedDateTime validFrom,
            ZonedDateTime validTo,
            CertificateExtensions extensions,
            PublicKey publicKey
    ) throws CertificateException, IOException {
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
        certInfo.set(X509CertInfo.SUBJECT, subject);
        certInfo.set(X509CertInfo.ISSUER, issuer);
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        if (extensions != null) {
            certInfo.set(X509CertInfo.EXTENSIONS, extensions);
        }
        return new X509CertImpl(certInfo);
    }

    public static GeneralNames createGeneralNames(List<GeneralName> names) {
        GeneralNames subjectAlternativeNames = new GeneralNames();
        names.forEach(subjectAlternativeNames::add);
        return subjectAlternativeNames;
    }

    public static Optional<Object> getAttribute(PKCS10 pkcs10, ObjectIdentifier oid) {
        return pkcs10.getAttributes().getAttributes().stream()
                .filter(p -> p.getAttributeId().equals(oid))
                .map(PKCS10Attribute::getAttributeValue)
                .findFirst();
    }

    public static CertificateExtensions getCertificateExtensions(PKCS10 pkcs10) {
        return (CertificateExtensions) getAttribute(pkcs10, PKCS9Attribute.EXTENSION_REQUEST_OID).orElse(null);
    }
}
