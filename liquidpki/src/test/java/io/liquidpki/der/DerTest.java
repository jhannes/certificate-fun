package io.liquidpki.der;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DerTest {

    @Test
    void shouldSerializeBoolean() throws IOException {
        assertThat(serializeAndDeserialize(new Der.BOOLEAN(true)).boolValue()).isTrue();
        assertThat(serializeAndDeserialize(new Der.BOOLEAN(false)).boolValue()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(longs = {42, 100, 5000})
    void shouldSerializeInteger(long value) throws IOException {
        assertThat(serializeAndDeserialize(new Der.INTEGER(value)).longValue()).isEqualTo(value);
    }

    @Test
    void shouldSerializeUTFTime() throws IOException {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS);
        assertThat(serializeAndDeserialize(new Der.UTCTime(dateTime)).getDateTime()).isEqualTo(dateTime);
    }

    @Test
    void shouldSerializeOctetString() throws IOException {
        String shortString = "0123456790123456789012345678901234567890123456789";
        String longString = shortString + shortString + shortString + shortString;
        String veryLongString = longString + longString + longString + longString + longString;

        assertThat(serializeAndDeserialize(new Der.OCTET_STRING(shortString.getBytes())).byteArray()).isEqualTo(shortString.getBytes());
        assertThat(serializeAndDeserialize(new Der.OCTET_STRING(longString.getBytes())).byteArray()).isEqualTo(longString.getBytes());
        assertThat(serializeAndDeserialize(new Der.OCTET_STRING(veryLongString.getBytes())).byteArray()).isEqualTo(veryLongString.getBytes());

        assertThat(new Der.OCTET_STRING(veryLongString.getBytes()).valueLength()).isEqualTo(veryLongString.length());
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.2", "5.3", "5.10.10", "5.10.127", "5.10.128", "3.2.16383", "3.2.16384", "3.2.32767"})
    public void shouldSerializeObjectName(String type) throws IOException {
        Der.OBJECT_IDENTIFIER der = new Der.OBJECT_IDENTIFIER(type);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        der.write(buffer);
        System.out.println(Base64.getEncoder().encodeToString(buffer.toByteArray()));
        assertThat(serializeAndDeserialize(der).getName()).isEqualTo(type);
    }

    @Test
    void shouldSerializeSequence() throws IOException {
        Der.SEQUENCE sequence = new Der.SEQUENCE(List.of(new Der.PRINTABLE_STRING("Hello world"), new Der.NULL()));
        Iterator<Der> iterator = serializeAndDeserialize(sequence).iterator();
        assertThat(((Der.PRINTABLE_STRING)iterator.next()).stringValue()).isEqualTo("Hello world");
        assertThat(iterator.next()).isInstanceOf(Der.NULL.class);
    }

    @Test
    public void shouldSerializeContextSpecificValue() throws IOException {
        DerContextSpecificValue der = serializeAndDeserialize(new DerContextSpecificValue(0x83, List.of(new Der.INTEGER(32))));
        assertThat(der.getTag()).isEqualTo(0x83);
        Iterator<Der> iterator = der.iterator();
        assertThat(((Der.INTEGER) iterator.next()).longValue()).isEqualTo(32);
    }


    private <T extends Der> T serializeAndDeserialize(T der) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        der.write(buffer);
        //noinspection unchecked
        return (T) Der.parse(buffer.toByteArray());
    }

}
