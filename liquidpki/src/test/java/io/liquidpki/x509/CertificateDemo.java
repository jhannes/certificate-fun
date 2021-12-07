package io.liquidpki.x509;

import io.liquidpki.common.Extension;
import io.liquidpki.common.X500Name;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class CertificateDemo {
    public static void main(String[] args) throws Exception {
        generateSelfSignedCertificate();
    }

    private static void generateSelfSignedCertificate() throws GeneralSecurityException {
        /*
        Map<String, String> props = new HashMap<>();
        Properties properties = new Properties();
        properties.load(new FileReader("local-self-signed.properties"));
        properties.forEach((k, v) -> props.put(k.toString(), v.toString()));

        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(props.get("keyStore.file")), props.get("keyStore.password").toCharArray());
        Key key = keyStore.getKey(props.get("keyStore.keyAlias"), props.get("keyStore.keyPassword").toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) keyStore.getCertificate(props.get("keyStore.keyAlias")).getPublicKey();

         */

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();


        SignedCertificate certificate = new CertificateInfo()
                .version(2)
                .serialNumber(6062104602511039190L)
                .subjectName(new X500Name().cn("Common Name").o("ORG"))
                .issuerName(new X500Name().cn("Common Name").o("ORG"))
                .publicKey(keyPair.getPublic())
                .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                .signWithKey(keyPair.getPrivate(), "SHA256withRSA");

        CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificate.toDer().toByteArray()));
        System.out.println(Base64.getEncoder().encodeToString(certificate.toDer().toByteArray()));
    }
}
