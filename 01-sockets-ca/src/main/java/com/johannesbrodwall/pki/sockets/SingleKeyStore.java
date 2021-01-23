package com.johannesbrodwall.pki.sockets;

import sun.security.pkcs10.PKCS10;
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;
import java.util.Set;

public class SingleKeyStore {

    private final KeyPairGenerator generator;

    private final String keyAlias;
    private final File filename;
    private final char[] storePassword;
    private final char[] keyPassword;
    private final KeyStore keyStore;

    public  SingleKeyStore(Properties properties, String prefix) throws GeneralSecurityException, IOException {
        this(
                properties.getOrDefault(prefix + ".alias", prefix).toString(),
                new File(properties.getOrDefault(prefix + ".keystore.filename", prefix + ".p12").toString()),
                properties.getProperty(prefix + ".keystore.password").toCharArray(),
                properties.getProperty(prefix + ".key.password").toCharArray()
        );
    }

    public SingleKeyStore(String keyAlias, File filename, char[] storePassword, char[] keyPassword) throws GeneralSecurityException, IOException {
        this.keyAlias = keyAlias;
        this.filename = filename;
        this.storePassword = storePassword;
        this.keyPassword = keyPassword;
        keyStore = KeyStore.getInstance("pkcs12");
        if (filename.exists()) {
            load();
        } else {
            keyStore.load(null);
        }

        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
    }

    public static TrustManager[] createTrustManager(X509Certificate certificate) throws IOException, GeneralSecurityException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null);
        trustStore.setCertificateEntry(certificate.getSubjectDN().getName(), certificate);
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();
    }


    public TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    public KeyManager[] getKeyManagers() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyPassword);
        return keyManagerFactory.getKeyManagers();
    }

    public void createCaCertificate(String issuer, ZonedDateTime validFrom, ZonedDateTime validTo) throws IOException, GeneralSecurityException {
        KeyPair keyPair = generateKeyPair();

        CertificateExtensions extensions = new CertificateExtensions();
        KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, true);
        keyUsageExtension.set(KeyUsageExtension.CRL_SIGN, true);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);

        boolean isCertificateAuthority = true;
        int certificationPathDepth = -1;
        BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(isCertificateAuthority, certificationPathDepth);
        extensions.set(BasicConstraintsExtension.NAME, basicConstraintsExtension);

        X509CertImpl certificateImpl = createCertificate(issuer, issuer, validFrom, validTo, extensions, keyPair.getPublic());
        certificateImpl.sign(keyPair.getPrivate(), "SHA512withRSA");

        setEntry(keyPair.getPrivate(), certificateImpl);
    }

    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
    }

    X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, ZonedDateTime validTo, PublicKey publicKey) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, UnrecoverableKeyException {
        CertificateExtensions extensions = new CertificateExtensions();
        GeneralNames subjectAlternativeNames = new GeneralNames();
        subjectAlternativeNames.add(new GeneralName(new DNSName(hostname)));
        extensions.set(SubjectAlternativeNameExtension.NAME,
                new SubjectAlternativeNameExtension(subjectAlternativeNames));

        X509CertImpl serverCertificate = createCertificate(subject, getSubjectDN(), validFrom, validTo, extensions, publicKey);
        serverCertificate.sign(getPrivateKey(), "SHA512withRSA");
        return serverCertificate;
    }

    public Certificate issueClientCertificate(String subject, ZonedDateTime validFrom, ZonedDateTime validTo, PublicKey publicKey) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException {
        X509CertImpl serverCertificate = createCertificate(subject, getSubjectDN(), validFrom, validTo, null, publicKey);
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


    public String getSubjectDN() throws KeyStoreException {
        return getCertificate().getSubjectDN().getName();
    }

    public X509Certificate getCertificate() throws KeyStoreException {
        return (X509Certificate) keyStore.getCertificate(keyAlias);
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
    }

    public void setEntry(PrivateKey key, Certificate certificate) throws KeyStoreException {
        keyStore.setKeyEntry(keyAlias, key, keyPassword, new Certificate[] { certificate });
    }

    public void load() throws IOException, GeneralSecurityException {
        try (FileInputStream stream = new FileInputStream(filename)) {
            keyStore.load(stream, storePassword);
        }
    }

    public void store() throws GeneralSecurityException, IOException {
        try (FileOutputStream stream = new FileOutputStream(filename)) {
            keyStore.store(stream, storePassword);
        }
    }

    public void exportCertificate() throws KeyStoreException, IOException, CertificateEncodingException {
        try (FileWriter writer = new FileWriter(keyAlias + ".crt")) {
            writeCertificate(writer, getCertificate());
        }
    }

    public static void writeCertificate(Writer writer, X509Certificate certificate) throws IOException, CertificateEncodingException {
        writer.write("-----BEGIN CERTIFICATE-----\n");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        writer.write(encodedCertText);
        writer.write("\n-----END CERTIFICATE-----");
        writer.flush();
    }

    public boolean isIssuedBy(String issuerDN) throws KeyStoreException {
        return getCertificate().getIssuerDN().toString().equals(issuerDN);
    }

    public void exportSigningRequest() throws IOException, GeneralSecurityException {
        Set<String> criticalExtensionOIDs = getCertificate().getCriticalExtensionOIDs();

        for (String oid : criticalExtensionOIDs) {
            byte[] extensionValue = getCertificate().getExtensionValue(oid);
        }
//        PKCS9Attribute.EXTENSION_REQUEST_OID
  //      new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, )


        PKCS10 certificationRequest = new PKCS10(getCertificate().getPublicKey());
//        certificationRequest.getAttributes().setAttribute(X509CertInfo.EXTENSIONS,
//                new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, ext));

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey());
        certificationRequest.encodeAndSign(new X500Name(getSubjectDN()), signature);

        try (PrintStream output = new PrintStream(new FileOutputStream(keyAlias + ".csr"))) {
            certificationRequest.print(output);
        }
    }

}
