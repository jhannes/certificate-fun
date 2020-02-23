package io.liquidpki.der;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DerTest {

    @Test
    void shouldSerializeBoolean() {
        assertThat(serializeAndDeserialize(new Der.BOOLEAN(true)).boolValue()).isTrue();
        assertThat(serializeAndDeserialize(new Der.BOOLEAN(false)).boolValue()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(longs = {42, 100, 5000, 0x100000, 0xfafa343434L})
    void shouldSerializeInteger(long value) {
        assertThat(serializeAndDeserialize(new Der.INTEGER(value)).longValue()).isEqualTo(value);
    }

    @Test
    void shouldSerializeCorrectIntegerLength() {
        assertThat(new Der.INTEGER(0xff).valueLength()).isEqualTo(1);
        assertThat(new Der.INTEGER(0xffff).valueLength()).isEqualTo(2);
        assertThat(new Der.INTEGER(0xffffff).valueLength()).isEqualTo(3);
        assertThat(new Der.INTEGER(0x1000000).valueLength()).isEqualTo(4);
        assertThat(new Der.INTEGER(0x100000000L).valueLength()).isEqualTo(5);
        assertThat(new Der.INTEGER(0x1000000000L).valueLength()).isEqualTo(5);
        assertThat(new Der.INTEGER(0x10000000000L).valueLength()).isEqualTo(6);
    }

    @Test
    void shouldSerializeUTFTime() {
        ZonedDateTime dateTime = ZonedDateTime.now().truncatedTo(ChronoUnit.SECONDS);
        assertThat(serializeAndDeserialize(new Der.UTCTime(dateTime)).getDateTime()).isEqualTo(dateTime);
        assertThat(Base64.getEncoder().encodeToString(new Der.UTCTime(dateTime).toByteArray()))
                .isEqualTo(Base64.getEncoder().encodeToString(Der.parse(new Der.UTCTime(dateTime).toByteArray()).toByteArray()));
    }

    @Test
    void shouldSerializeOctetString() {
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
    public void shouldSerializeObjectName(String type) {
        Der.OBJECT_IDENTIFIER der = new Der.OBJECT_IDENTIFIER(type);
        assertThat(serializeAndDeserialize(der).getName()).isEqualTo(type);
    }

    @Test
    void shouldSerializeSequence() {
        Der.SEQUENCE sequence = new Der.SEQUENCE(List.of(new Der.PRINTABLE_STRING("Hello world"), new Der.NULL()));
        Iterator<Der> iterator = serializeAndDeserialize(sequence).iterator();
        assertThat(((Der.PRINTABLE_STRING)iterator.next()).stringValue()).isEqualTo("Hello world");
        assertThat(iterator.next()).isInstanceOf(Der.NULL.class);
    }

    @Test
    void shouldCalculateCorrectLengthOfNestedSequences() {
        String shortString = "0123456790123456789012345678901234567890123456789";
        String longString = shortString + shortString + shortString + shortString;
        String veryLongString = longString + longString + longString + longString + longString;

        Der.SEQUENCE sequence = new Der.SEQUENCE(List.of(
                new Der.SEQUENCE(List.of(new Der.SEQUENCE(List.of(new Der.OCTET_STRING(veryLongString.getBytes()))))),
                new Der.PRINTABLE_STRING("test")));

        Der.SEQUENCE deserialized = serializeAndDeserialize(sequence);
        Iterator<Der> iterator = deserialized.iterator();
        Der.OCTET_STRING deserializedOctet = (Der.OCTET_STRING) ((Der.SEQUENCE) ((Der.SEQUENCE) iterator.next()).iterator().next()).iterator().next();
        Der.PRINTABLE_STRING deserializedString = (Der.PRINTABLE_STRING) iterator.next();
        assertThat(deserializedOctet.byteArray()).isEqualTo(veryLongString.getBytes());
        assertThat(deserializedString.stringValue()).isEqualTo("test");
    }

    @Test
    void shouldSerializeSequenceOfDates() {
        Der.SEQUENCE sequence = new Der.SEQUENCE(List.of(new Der.PRINTABLE_STRING("Hello world"), new Der.NULL()));
        Iterator<Der> iterator = serializeAndDeserialize(sequence).iterator();
        assertThat(((Der.PRINTABLE_STRING)iterator.next()).stringValue()).isEqualTo("Hello world");
        assertThat(iterator.next()).isInstanceOf(Der.NULL.class);
    }

    @Test
    public void shouldSerializeContextSpecificValue() {
        DerContextSpecificValue der = serializeAndDeserialize(new DerContextSpecificValue(0x83, new Der.INTEGER(32).toByteArray()));
        assertThat(der.getTag()).isEqualTo(0x83);
        assertThat(((Der.INTEGER) der.parse()).longValue()).isEqualTo(32);
    }

    @Test
    public void shouldSerializeComplexStructure() {
        Der.SEQUENCE name = new Der.SEQUENCE(List.of(
                new Der.SET(List.of(new Der.SEQUENCE(List.of(
                        new Der.OBJECT_IDENTIFIER("2.5.4.3"),
                        new Der.PRINTABLE_STRING("Issuer name")
                )))),
                new Der.SET(List.of(new Der.SEQUENCE(List.of(
                        new Der.OBJECT_IDENTIFIER("2.5.4.10"),
                        new Der.PRINTABLE_STRING("Example Org")
                ))))
        ));

        Der.SEQUENCE actual = serializeAndDeserialize(name);
        assertThat(actual.first()).isInstanceOf(Der.SET.class);
    }

    private <T extends Der> T serializeAndDeserialize(T der) {
        //noinspection unchecked
        T deserialized = (T) Der.parse(der.toByteArray());
        assertThat(Der.toHex(der.toByteArray()))
                .isEqualTo(Der.toHex(deserialized.toByteArray()));
        return deserialized;
    }
}
