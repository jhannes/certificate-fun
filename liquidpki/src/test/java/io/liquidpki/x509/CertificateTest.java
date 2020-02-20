package io.liquidpki.x509;

import io.liquidpki.common.X501Name;
import io.liquidpki.der.Der;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateTest {

    @Test
    void shouldSerializeValidity() throws IOException {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS).withZoneSameInstant(ZoneId.of("UTC"));

        X509Certificate.Validity validity = new X509Certificate.Validity(serializeAndDeserialize(new X509Certificate.Validity(dateTime.minusWeeks(1), dateTime.plusYears(10)).toDer()));

        assertThat(validity.getNotBefore()).isEqualTo(dateTime.minusWeeks(1));
        assertThat(validity.getNotAfter()).isEqualTo(dateTime.plusYears(10));
    }

    @Test
    void shouldSerializeName() throws IOException {
        X501Name name = new X501Name().cn("My Common Name").o("My Organization");
        X501Name clone = new X501Name(serializeAndDeserialize(name.toDer()));

        assertThat(clone.cn()).isEqualTo("My Common Name");
        assertThat(clone.o()).isEqualTo("My Organization");
    }

    private Der serializeAndDeserialize(Der der) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        der.write(buffer);
        return Der.parse(buffer.toByteArray());
    }

}
