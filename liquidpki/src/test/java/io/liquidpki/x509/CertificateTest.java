package io.liquidpki.x509;

import io.liquidpki.common.Extension;
import io.liquidpki.common.X500Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.Oid;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateTest {

    @Test
    void shouldSerializeX501Name() {
        X500Name name = new X500Name().cn("Issuer name").ou("Organization Unit").o("Example Org");
        X500Name restored = new X500Name(name.toDer());
        assertThat(restored.ou()).isEqualTo("Organization Unit");

        X500Name deserialized = new X500Name(Der.parse(name.toDer().toByteArray()));
        assertThat(deserialized.o()).isEqualTo("Example Org");

        assertThat(Der.toHex(name.toDer().toByteArray()))
                .isEqualTo(Der.toHex(restored.toDer().toByteArray()))
                .isEqualTo(Der.toHex(deserialized.toDer().toByteArray()));
    }

    @Test
    void shouldParseAndOutputX501Name() {
        X500Name name = new X500Name("CN=Certificate Corp, O=no, OU=Test");
        assertThat(name.print()).isEqualTo("CN=Certificate Corp,O=no,OU=Test");
    }

    @Test
    void shouldThrowOnMisformattedX501Name() {
        assertThatThrownBy(() -> new X500Name("Not a DN"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid name: Not a DN");
    }

    @Test
    void shouldThrowOnUnknownAttributeName() {
        assertThatThrownBy(() -> new X500Name("ZZ=invalid type"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown DN type name ZZ");
    }

    @Test
    void shouldSerializedUnsignedCertificate() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        CertificateInfo certificate = new CertificateInfo()
                .version(2)
                .signature(Oid.getSignatureAlgorithm(keyPair.getPrivate().getAlgorithm()))
                .issuerName(new X500Name().cn("Issuer name").ou("Organization Unit"))
                .subjectName(new X500Name().cn("Subject name").ou("Organization Unit"))
                .validity(ZonedDateTime.now().minusDays(1), ZonedDateTime.now().plusDays(200))
                .publicKey(keyPair.getPublic())
                .addExtension(new Extension.BasicConstraintExtensionType().ca(true))
                .addExtension(new Extension.KeyUsageExtensionType().keyCertSign(true))
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.com").ipAddress("127.0.0.1"));

        CertificateInfo restored = new CertificateInfo(Der.parse(certificate.toDer().toByteArray()));

        assertThat(restored.version()).isEqualTo(2);
        assertThat(restored.issuer.ou()).isEqualTo("Organization Unit");
        assertThat(restored.extensions().sanExtension().ipAddress()).isEqualTo("127.0.0.1");
        assertThat(restored.extensions().sanExtension().dnsName()).isEqualTo("www.example.com");
        assertThat(restored.extensions().keyUsage().keyCertSign()).isEqualTo(true);
        assertThat(restored.extensions().keyUsage().keyEncipherment()).isEqualTo(false);
        assertThat(restored.extensions().extension(Extension.BasicConstraintExtensionType.class).ca()).isTrue();

        RSAPublicKey publicKey = restored.publicKey();
        assertThat(publicKey).isEqualTo(keyPair.getPublic());
    }

    @Test
    void shouldSerializeCertificate() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        SignedCertificate certificate = new CertificateInfo()
                .version(2)
                .serialNumber(6062104602511039190L)
                .issuerName(new X500Name().cn("Common Name").o("Test Organization"))
                .validity(ZonedDateTime.now().minusDays(1), ZonedDateTime.now().plusDays(200))
                .subjectName(new X500Name().cn("Common Name").o("Test Organization"))
                .publicKey(keyPair.getPublic())
                .addExtension(new Extension.SANExtensionType().dnsName("www.example.com"))
                .addExtension(new Extension.KeyUsageExtensionType().keyEncipherment(true))
                .signWithKey(keyPair.getPrivate(), "SHA256withRSA");

        Der der = serializeAndDeserialize(certificate.toDer());

        SignedCertificate clone = new SignedCertificate(der);
        assertThat(clone.tbsCertificate.issuer.cn()).isEqualTo(certificate.tbsCertificate.issuer.cn());
        assertThat(clone.tbsCertificate.signature.getAlgorithmOid()).isEqualTo(certificate.tbsCertificate.signature.getAlgorithmOid());
        assertThat(clone.signatureValue.bytesValue()).isEqualTo(certificate.signatureValue.bytesValue());
    }

    @Test
    void shouldVerifyCertificateSignature() throws GeneralSecurityException {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        SignedCertificate certificate = new CertificateInfo()
                .issuerName(new X500Name().cn("Common Name").o("Test Organization"))
                .subjectName(new X500Name().cn("www.example.com").o("Test Org"))
                .publicKey(keyPair.getPublic())
                .signWithKey(keyPair.getPrivate(), "SHA512withRSA");

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(certificate.tbsCertificate.publicKey());
        signature.update(certificate.tbsCertificate.toDer().toByteArray());
        assertThat(signature.verify(certificate.signatureValue.bytesValue())).isTrue();
    }

    @Test
    void shouldSerializeValidity() {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS).withZoneSameInstant(ZoneId.of("UTC"));

        CertificateInfo.Validity validity = new CertificateInfo.Validity(dateTime.minusWeeks(1), dateTime.plusYears(10));
        CertificateInfo.Validity restored = new CertificateInfo.Validity(serializeAndDeserialize(validity.toDer()));

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
        X500Name name = new X500Name().cn("My Common Name").o("My Organization");
        X500Name clone = new X500Name(serializeAndDeserialize(name.toDer()));

        assertThat(clone.cn()).isEqualTo("My Common Name");
        assertThat(clone.o()).isEqualTo("My Organization");
    }

    @Test
    void shouldReadCertificate() throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Objects.requireNonNull(getClass().getResourceAsStream("/github-cert.crt")).transferTo(buffer);
        List<byte[]> bytes = readPemObjects(buffer);

        SignedCertificate certificate = new SignedCertificate(bytes.get(0));
        certificate.dump(System.out, true);
        assertThat(certificate.tbsCertificate.subject.o()).isEqualTo("GitHub, Inc.");
        assertThat(certificate.tbsCertificate.extensions.sanExtension().dnsName()).isEqualTo("github.com");
    }

    private Der serializeAndDeserialize(Der der) {
        return Der.parse(der.toByteArray());
    }


    public static List<byte[]> readPemObjects(ByteArrayOutputStream buffer) {
        // 🤮🤢
        List<byte[]> certificatesDer = new ArrayList<>();
        String content = buffer.toString();
        StringBuilder currentCertificate = null;
        for (String line : content.split("\r?\n")) {
            if (line.matches("-----BEGIN [A-Z ]+-----")) {
                if (currentCertificate != null) {
                    System.err.println("No!");
                }
                currentCertificate = new StringBuilder();
            } else if (line.matches("-----END [A-Z ]+-----")) {
                if (currentCertificate == null) {
                    System.err.println("No!");
                } else {
                    certificatesDer.add(Base64.getDecoder().decode(currentCertificate.toString()));
                    currentCertificate = null;
                }
            } else {
                if (currentCertificate == null) {
                    System.err.println("No!");
                } else {
                    currentCertificate.append(line);
                }
            }
        }
        if (currentCertificate != null) {
            System.err.println("NO!");
        }
        return certificatesDer;
    }

}
