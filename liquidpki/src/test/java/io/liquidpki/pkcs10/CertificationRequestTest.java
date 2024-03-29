package io.liquidpki.pkcs10;

import io.liquidpki.common.Extension;
import io.liquidpki.common.X500Name;
import io.liquidpki.der.Der;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class CertificationRequestTest {

    @Test
    void shouldSerializeCertificationRequest() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        CertificationRequest request = new CertificationRequestInfo()
                .subject(new X500Name().cn("www.example.net").o("Example Company Inc"))
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.net"))
                .publicKey(publicKey)
                .signWithKey(keyPair.getPrivate());

        System.out.println(Base64.getEncoder().encodeToString(request.toDer().toByteArray()));
        CertificationRequest restored = new CertificationRequest(Der.parse(request.toDer().toByteArray()));

        assertThat(restored.certificationRequestInfo.subject().cn()).isEqualTo("www.example.net");
    }

    @Test
    void shouldVerifyCertificationRequestSignature() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        CertificationRequest request = new CertificationRequestInfo()
                .subject(new X500Name().cn("www.example.net").o("Example Company Inc"))
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.net"))
                .publicKey(publicKey)
                .signWithKey(keyPair.getPrivate());

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(request.certificationRequestInfo.publicKey());
        signature.update(request.certificationRequestInfo.toDer().toByteArray());
        assertThat(signature.verify(request.signature.bytesValue())).isTrue();
    }

    @Test
    void shouldSerializeCertificationRequestInfo() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        CertificationRequestInfo request = new CertificationRequestInfo()
                .version(0)
                .subject(new X500Name().cn("www.example.net").o("Example Company Inc"))
                .publicKey(publicKey);

        CertificationRequestInfo restored = new CertificationRequestInfo(
                Der.parse(request.toDer().toByteArray())
        );

        assertThat(restored.subject().cn()).isEqualTo("www.example.net");
        assertThat(restored.publicKey()).isEqualTo(publicKey);
    }


    @Test
    void shouldSerializeExtensions() throws NoSuchAlgorithmException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        CertificationRequestInfo request = new CertificationRequestInfo()
                .subject(new X500Name().cn("Example Company Inc"))
                .publicKey(publicKey)
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.net"));

        CertificationRequestInfo restored = new CertificationRequestInfo(
                Der.parse(request.toDer().toByteArray())
        );

        assertThat(restored.extensions().sanExtension().dnsName()).isEqualTo("www.example.net");
    }
}
