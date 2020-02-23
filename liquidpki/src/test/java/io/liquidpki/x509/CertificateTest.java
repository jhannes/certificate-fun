package io.liquidpki.x509;

import io.liquidpki.common.Extension;
import io.liquidpki.common.X501Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.Oid;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateTest {

    @Test
    void shouldSerializeX501Name() {
        X501Name name = new X501Name().cn("Issuer name").ou("Organization Unit").o("Example Org");
        X501Name restored = new X501Name(name.toDer());
        assertThat(restored.ou()).isEqualTo("Organization Unit");

        X501Name deserialized = new X501Name(Der.parse(name.toDer().toByteArray()));
        assertThat(deserialized.o()).isEqualTo("Example Org");

        assertThat(Der.toHex(name.toDer().toByteArray()))
                .isEqualTo(Der.toHex(restored.toDer().toByteArray()))
                .isEqualTo(Der.toHex(deserialized.toDer().toByteArray()));
    }

    @Test
    void shouldSerializedUnsignedCertificate() throws NoSuchAlgorithmException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate.TbsCertificate certificate = new X509Certificate.TbsCertificate()
                .version(2)
                .signature(Oid.getSignatureAlgorithm(keyPair.getPrivate().getAlgorithm()))
                .issuerName(new X501Name().cn("Issuer name").ou("Organization Unit"))
                .subjectName(new X501Name().cn("Subject name").ou("Organization Unit"))
                .validity(ZonedDateTime.now().minusDays(1), ZonedDateTime.now().plusDays(200))
                .publicKey(keyPair.getPublic())
                .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.com").ipAddress("127.0.0.1"));

        X509Certificate.TbsCertificate restored = new X509Certificate.TbsCertificate(Der.parse(certificate.toDer().toByteArray()));

        assertThat(restored.version()).isEqualTo(2);
        assertThat(restored.issuer.ou()).isEqualTo("Organization Unit");
        assertThat(restored.extensions().sanExtension().ipAddress()).isEqualTo("127.0.0.1");
        assertThat(restored.extensions().sanExtension().dnsName()).isEqualTo("www.example.com");
        assertThat(restored.extensions().keyUsage().keyCertSign()).isEqualTo(true);
        assertThat(restored.extensions().keyUsage().keyEncipherment()).isEqualTo(false);
    }

    @Test
    void shouldSerializeCertificate() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate certificate = new X509Certificate()
                .tbsCertificate(new X509Certificate.TbsCertificate()
                        .version(1)
                        .issuerName(new X501Name().cn("Common Name").o("Test Organization"))
                        .validity(ZonedDateTime.now().minusDays(1), ZonedDateTime.now().plusDays(200))
                        .subjectName(new X501Name().cn("www.example.com").o("Test Org"))
                        .publicKey(keyPair.getPublic())
                        .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true)))
                .signatureAlgorithm(keyPair.getPrivate())
                .signWithKey(keyPair.getPrivate());

        System.out.println(Base64.getEncoder().encodeToString(certificate.toDer().toByteArray()));
        Der der = serializeAndDeserialize(certificate.toDer());

        X509Certificate clone = new X509Certificate(der);
        assertThat(clone.tbsCertificate.issuer.cn()).isEqualTo(certificate.tbsCertificate.issuer.cn());
        assertThat(clone.tbsCertificate.signature.getAlgorithmOid()).isEqualTo(certificate.tbsCertificate.signature.getAlgorithmOid());
        assertThat(clone.signatureValue.byteArray()).isEqualTo(certificate.signatureValue.byteArray());
    }



    @Test
    void shouldSerializeValidity() {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS).withZoneSameInstant(ZoneId.of("UTC"));

        X509Certificate.Validity validity = new X509Certificate.Validity(dateTime.minusWeeks(1), dateTime.plusYears(10));
        X509Certificate.Validity restored = new X509Certificate.Validity(serializeAndDeserialize(validity.toDer()));

        assertThat(restored.getNotBefore()).isEqualTo(dateTime.minusWeeks(1));
        assertThat(restored.getNotAfter()).isEqualTo(dateTime.plusYears(10));

        byte[] serialized = validity.toDer().toByteArray();
        byte[] restore = Der.parse(serialized).toByteArray();
        assertThat(Base64.getEncoder().encodeToString(serialized))
                .isEqualTo(Base64.getEncoder().encodeToString(restore));
    }

    @Test
    void shouldDeserializeValidity() {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS).withZoneSameInstant(ZoneId.of("UTC"));

        Der.SEQUENCE der = new Der.SEQUENCE(List.of(new Der.UTCTime(dateTime.minusWeeks(1)), new Der.UTCTime(dateTime.plusMonths(6))));
        Der restored = Der.parse(der.toByteArray());
        String expected = Der.toHex(restored.toByteArray());
        assertThat(Der.toHex(der.toByteArray()))
                .isEqualTo(expected);
    }


    @Test
    void shouldSerializeName() {
        X501Name name = new X501Name().cn("My Common Name").o("My Organization");
        X501Name clone = new X501Name(serializeAndDeserialize(name.toDer()));

        assertThat(clone.cn()).isEqualTo("My Common Name");
        assertThat(clone.o()).isEqualTo("My Organization");
    }

    private Der serializeAndDeserialize(Der der) {
        return Der.parse(der.toByteArray());
    }

}
