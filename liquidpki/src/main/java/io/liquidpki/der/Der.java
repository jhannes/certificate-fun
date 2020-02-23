package io.liquidpki.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/***
 * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
 */
public interface Der {

    Map<Integer, Function<DerValue, Der>> TAG_FACTORY = tagMap();

    static Map<Integer, Function<DerValue, Der>> tagMap() {
        Map<Integer, Function<DerValue, Der>> tagMap = new java.util.HashMap<>();
        tagMap.put(0x01, BOOLEAN::new);
        tagMap.put(0x02, INTEGER::new);
        tagMap.put(0x03, BIT_STRING::new);
        tagMap.put(0x04, OCTET_STRING::new);
        tagMap.put(0x05, NULL::new);
        tagMap.put(0x06, OBJECT_IDENTIFIER::new);
        tagMap.put(0x0C, UFT8_STRING::new);
        tagMap.put(0x13, PRINTABLE_STRING::new);
        tagMap.put(0x17, UTCTime::new);
        tagMap.put(0x30, SEQUENCE::new);
        tagMap.put(0x31, SET::new);
        return tagMap;
    }

    static Der parse(byte[] derBytes) {
        return parse(derBytes, 0);
    }

    static Der parse(byte[] derBytes, int offset) {
        return parse(new DerValue(derBytes, offset));
    }

    static Der parse(DerValue derValue) {
        Function<DerValue, Der> factory =  Der.TAG_FACTORY.get(derValue.getTag());
        if (factory != null) return factory.apply(derValue);
        if ((derValue.getTag() & 0b11000000) == 0b10000000) {
            return new DerContextSpecificValue(derValue);
        }
        return derValue;
    }

    void write(OutputStream output) throws IOException;

    void output(PrintStream out, String indent);

    int fullLength();

    int getTag();

    default byte[] toByteArray() {
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            write(buffer);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Can never happen ", e);
        }
    }


    class BOOLEAN extends DerValue {
        public BOOLEAN(DerValue derValue) {
            super(derValue);
        }

        public BOOLEAN(boolean booleanValue) {
            super(0x1, new byte[] { booleanValue ? (byte)0xff : 0 });
        }

        @Override
        protected String printValue() {
            int b = unsignedVal(0);
            if (b == 0) return "false";
            if (b == 0xff) return "true";
            return "0x" + Integer.toString(b, 16);
        }

        public boolean boolValue() {
            return unsignedVal(0) != 0;
        }

    }

    class INTEGER extends DerValue {
        public INTEGER(DerValue derValue) {
            super(derValue);
        }

        public INTEGER(long value) {
            super(0x02, asBytes(value));
        }

        public INTEGER(BigInteger value) {
            super(0x02, value.toByteArray());
        }

        @Override
        protected String printValue() {
            if (valueLength() == 8) {
                return "0x" + Long.toString(longValue(), 16);
            }
            return super.printValue();
        }

        public long longValue() {
            return bytesToLong();
        }

        public BigInteger toBigInteger() {
            return new BigInteger(byteArray());
        }
    }

    class BIT_STRING extends DerValue {
        public BIT_STRING(DerValue derValue) {
            super(derValue);
        }

        public BIT_STRING(byte[] value, int unusedBytes) {
            super(0x3, join(unusedBytes, value));
        }

        private static byte[] join(int unusedBytes, byte[] value) {
            byte[] bytes = new byte[value.length + 1];
            bytes[0] = (byte) (0xff & unusedBytes);
            System.arraycopy(value, 0, bytes, 1, value.length);
            return bytes;
        }

        public BIT_STRING(byte[] bytes) {
            this(bytes, 0);
        }

        public BIT_STRING(long value) {
            this(asBytes(value), 0);
        }

        public long longValue() {
            return bytesToLong();
        }

        public byte[] byteArray() {
            return super.byteArray();
        }

        public Der parse() {
            return Der.parse(atOffset(1));
        }
    }

    class OCTET_STRING extends DerValue {
        public OCTET_STRING(DerValue derValue) {
            super(derValue);
        }

        public OCTET_STRING(byte[] bytes) {
            super(0x4, bytes);
        }

        public byte[] byteArray() {
            return super.byteArray();
        }
    }

    class NULL extends DerValue {
        public NULL(DerValue derValue) { super(derValue); }

        public NULL() {
            super(0x5, new byte[0]);
        }
    }

    class OBJECT_IDENTIFIER extends DerValue {
        public OBJECT_IDENTIFIER(DerValue derValue) {
            super(derValue);
        }

        public OBJECT_IDENTIFIER(String oid) {
            super(0x6, serializeOid(oid));
        }

        private static byte[] serializeOid(String oid) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            String[] parts = oid.split("\\.");
            int firstNode = Integer.parseInt(parts[0]), secondNode = Integer.parseInt(parts[1]);
            buffer.write(firstNode*40 + secondNode);
            for (int i = 2; i < parts.length; i++) {
                long node = Long.parseLong(parts[i]);
                int extraBytesRemaining = ((Long.toString(node, 2).length() - 1) / 7);
                while (extraBytesRemaining > 0) {
                    buffer.write((int)(0b1000_0000 | ((node >> 7*extraBytesRemaining) & 0b0111_1111)));
                    extraBytesRemaining--;
                }
                buffer.write((int)(node & 0b0111_1111));
            }
            return buffer.toByteArray();
        }

        @Override
        protected String printValue() {
            return getObjectIdentifier();
        }

        public String getName() {
            String name = Oid.get(getObjectIdentifier());
            return name != null ? (name + " (" + getObjectIdentifier() + ")") : getObjectIdentifier();
        }

        public String getObjectIdentifier() {
            int firstTwoNodes = unsignedVal(0);
            StringBuilder value = new StringBuilder(firstTwoNodes / 40 + "." + firstTwoNodes % 40);
            int pos = 1;
            while (pos< valueLength()) {
                int node = 0;
                int octet;
                do {
                    octet = unsignedVal(pos++);
                    node = node << 7 | (octet & ~0x80);
                } while (octet >= 0x80);
                value.append(".").append(node);
            }
            return value.toString();
        }
    }

    abstract class DerString extends DerValue {
        protected DerString(DerValue derValue) {
            super(derValue);
        }

        protected DerString(int tag, String value) {
            super(tag, value.getBytes());
        }

        @Override
        protected String printValue() {
            return "\"" + stringValue() + "\"";
        }

        public String stringValue() {
            return stringValue(Charset.defaultCharset());
        }
    }

    class UFT8_STRING extends DerString {

        public UFT8_STRING(DerValue derValue) {
            super(derValue);
        }

        public UFT8_STRING(String value) {
            super(0xc, value);
        }

        @Override
        public String stringValue() {
            return super.stringValue(StandardCharsets.UTF_8);
        }
    }

    class PRINTABLE_STRING extends DerString {

        public PRINTABLE_STRING(DerValue derValue) {
            super(derValue);
        }

        public PRINTABLE_STRING(String value) {
            super(0x13, value);
        }
    }


    class UTCTime extends DerValue {
        public UTCTime(DerValue derValue) {
            super(derValue);
        }

        public UTCTime(ZonedDateTime dateTime) {
            super(0x17, dateTime.format(DateTimeFormatter.ofPattern("yyMMddHHmmssX")).getBytes());
        }

        @Override
        protected String printValue() {
            return getDateTime().toString();
        }

        public ZonedDateTime getDateTime() {
            String value = stringValue(Charset.defaultCharset());
            String century = value.charAt(0) < '5' ? "20" : "19";
            return ZonedDateTime.parse(century + value, DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"));
        }
    }

    class SEQUENCE extends DerCollection {
        public SEQUENCE(DerValue derValue) {
            super(derValue);
        }

        public SEQUENCE(List<? extends Der> children) {
            super(0x30, children);
        }

    }

    class SET extends DerCollection {
        public SET(DerValue derValue) {
            super(derValue);
        }

        public SET(byte[] encoded) {
            super(new DerValue(0x31, encoded));
        }

        public SET(List<Der> children) {
            super(0x31, children);
        }
    }

    char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length*2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    static byte[] asBytes(long value) {
        int bytes = bytesInNumber(value);
        byte[] result = new byte[bytes];
        for (int i = bytes-1; i >= 0; i--) {
            result[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    static void writeLength(OutputStream buffer, int length) throws IOException {
        if (length < 0x80) {
            buffer.write(0xff & length);
        } else {
            int bytesInLengthField = bytesInNumber(length) + 1;
            buffer.write((byte)(0b10000000 | (0xff & (bytesInLengthField-1))));
            for (int i = 0; i < bytesInLengthField - 1; i++) {
                buffer.write((byte)(0xff & (length >> (bytesInLengthField-2-i)*8)));
            }
        }
    }

    static int bytesInNumber(long value) {
        return (Long.toString(value, 16).length() + 1) / 2;
    }
}
