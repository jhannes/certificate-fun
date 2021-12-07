package com.johannesbrodwall.pki.ca;

import com.johannesbrodwall.pki.util.SslUtil;
import io.liquidpki.common.Extension;
import io.liquidpki.common.X500Name;
import io.liquidpki.der.Der;
import io.liquidpki.pkcs10.CertificationRequest;
import io.liquidpki.x509.CertificateInfo;
import io.liquidpki.x509.SignedCertificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Optional;

public class LiquidPkiCertificateAuthority implements CertificateAuthority {
    private final Period validity;
    private final PrivateKey caPrivateKey;
    private final X509Certificate caCertificate;
    private final X500Name caSubjectDN;

    public LiquidPkiCertificateAuthority(Period validity, KeyPair caKeyPair, String issuerDN, ZonedDateTime validFromTime) throws GeneralSecurityException {
        this.validity = validity;
        this.caPrivateKey = caKeyPair.getPrivate();

        caSubjectDN = new X500Name(issuerDN);
        SignedCertificate certificate = new CertificateInfo()
                .version(2)
                .issuerName(caSubjectDN)
                .subjectName(caSubjectDN)
                .validity(validFromTime, validFromTime.plus(validity))
                .publicKey(caKeyPair.getPublic())
                .addExtension(new Extension.BasicConstraintExtensionType().ca(true))
                .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                .signWithKey(caPrivateKey, "SHA512withRSA");
        caCertificate = toX509(certificate);

    }

    public LiquidPkiCertificateAuthority(KeyStore keyStore, Period validity) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        this.validity = validity;
        String alias = keyStore.aliases().nextElement();
        caPrivateKey = (PrivateKey) keyStore.getKey(alias, null);
        caCertificate = (X509Certificate) keyStore.getCertificate(alias);
        caSubjectDN = new X500Name(Der.parse(caCertificate.getSubjectX500Principal().getEncoded()));
    }

    private X509Certificate toX509(SignedCertificate signedSignature) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(signedSignature.toDer().toByteArray()));
    }

    @Override
    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    @Override
    public X509Certificate issueServerCertificate(String hostname, String subject, ZonedDateTime validFrom, PublicKey publicKey) throws GeneralSecurityException {
        return signCertificate(createCertificateToBeSigned(new X500Name(subject), validFrom, publicKey).addExtension(new Extension.SANExtensionType().dnsName(hostname)));
    }

    @Override
    public X509Certificate issueCertificate(String subject, ZonedDateTime validFrom, PublicKey publicKey, Optional<byte[]> csrForExtensions) throws GeneralSecurityException {
        CertificateInfo tbsCertificate = createCertificateToBeSigned(new X500Name(subject), validFrom, publicKey);
        csrForExtensions.map(Der::parse)
                .map(CertificationRequest::new)
                .map(csr -> csr.info().extensions())
                .ifPresent(tbsCertificate::extensions);
        return signCertificate(tbsCertificate);
    }

    @Override
    public X509Certificate issueCertificate(byte[] csrBytes, ZonedDateTime validFrom) throws GeneralSecurityException {
        CertificationRequest certificationRequest = new CertificationRequest(Der.parse(csrBytes));
        return signCertificate(createCertificateToBeSigned(certificationRequest.info().subject(), validFrom, certificationRequest.info().publicKey())
                .extensions(certificationRequest.info().extensions()));
    }

    private CertificateInfo createCertificateToBeSigned(X500Name subject, ZonedDateTime validFrom, PublicKey publicKey) {
        return new CertificateInfo()
                .version(2)
                .subjectName(subject)
                .validity(validFrom, validFrom.plus(validity))
                .issuerName(caSubjectDN)
                .publicKey(publicKey);
    }

    private X509Certificate signCertificate(CertificateInfo tbsCertificate) throws GeneralSecurityException {
        return toX509(tbsCertificate.signWithKey(caPrivateKey, "SHA512withRSA"));
    }

    @Override
    public KeyStore getKeyStore() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        return SslUtil.createKeyStore(caPrivateKey, null, caCertificate);
    }
}
