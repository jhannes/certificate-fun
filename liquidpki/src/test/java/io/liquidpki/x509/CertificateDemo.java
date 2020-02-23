package io.liquidpki.x509;

import io.liquidpki.common.Extension;
import io.liquidpki.common.X501Name;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class CertificateDemo {
    public static void main(String[] args) throws Exception {
        generateSelfSignedCertificate();
    }

    private static void generateSelfSignedCertificate() throws IOException, GeneralSecurityException {
        Map<String, String> props = new HashMap<>();
        Properties properties = new Properties();
        properties.load(new FileReader("local-self-signed.properties"));
        properties.forEach((k, v) -> props.put(k.toString(), v.toString()));

        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(props.get("keyStore.file")), props.get("keyStore.password").toCharArray());
        Key key = keyStore.getKey(props.get("keyStore.keyAlias"), props.get("keyStore.keyPassword").toCharArray());
        RSAPublicKey publicKey = (RSAPublicKey) keyStore.getCertificate(props.get("keyStore.keyAlias")).getPublicKey();

        X509Certificate certificate = new X509Certificate()
                .tbsCertificate(new X509Certificate.TbsCertificate()
                        .version(2)
                        .serialNumber(6062104602511039190L)
                        .subjectName(new X501Name().cn(props.get("cn")).o(props.get("o")))
                        .issuerName(new X501Name().cn(props.get("cn")).o(props.get("o")))
                        .publicKey(publicKey)
                        .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                )
                .signWithKey((PrivateKey) key);

        System.out.println(Base64.getEncoder().encodeToString(certificate.toDer().toByteArray()));
    }
}
