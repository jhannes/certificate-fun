package io.liquidpki.ca;

import io.liquidpki.common.Extension;
import io.liquidpki.x501.X501Name;
import io.liquidpki.x509.X509Certificate;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class CaCertificateBuilder {
    private final KeyPair keyPair;
    private X501Name name;

    public CaCertificateBuilder() throws NoSuchAlgorithmException {
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        name = new X501Name()
                .cn("Master key")
                .o("My Example org");
    }


    public static void main(String[] args) throws GeneralSecurityException, IOException {
        new CaCertificateBuilder()
                .save(System.out);
    }

    private void save(OutputStream out) throws IOException, GeneralSecurityException {
        X509Certificate certificate = new X509Certificate()
                .tbsCertificate(new X509Certificate.TbsCertificate()
                        .subjectName(name)
                        .issuerName(name)
                        .publicKey(keyPair.getPublic())
                        .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                )
                .signWithKey(keyPair.getPrivate());
        certificate.toDer().output(new PrintStream(out), "");
        certificate.dump(new PrintStream(out), false);
    }
}
