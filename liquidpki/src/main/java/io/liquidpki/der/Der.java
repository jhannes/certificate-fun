package io.liquidpki.der;

import java.io.PrintStream;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.Map;
import java.util.function.Function;

/***
 * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
 */
public interface Der {

    Map<Integer, Function<DerValue, Der>> TAG_FACTORY = Map.of(
            0x01, BOOLEAN::new,
            0x02, INTEGER::new,
            0x03, BIT_STRING::new,
            0x04, OCTET_STRING::new,
            0x06, OBJECT_IDENTIFIER::new,
            0x13, PRINTABLE_STRING::new,
            0x17, UTCTime::new,
            0x30, SEQUENCE::new,
            0x31, SET::new
    );

    static Der parse(byte[] derBytes) {
        return parse(derBytes, 0);
    }

    static Der parse(byte[] derBytes, int offset) {
        DerValue derValue = new DerValue(derBytes, offset);
        Function<DerValue, Der> factory =  Der.TAG_FACTORY.get(derValue.getTag());
        if (factory != null) return factory.apply(derValue);
        if ((derValue.getTag() & 0b11000000) == 0b10000000) {
            return new DerContextSpecificValue(derValue);
        }
        return derValue;
    }

    String toHexBytes();

    void output(PrintStream out, String indent);

    int fullLength();


    class BOOLEAN extends DerValue {
        public BOOLEAN(DerValue derValue) {
            super(derValue);
        }

        @Override
        protected String printValue() {
            int b = unsignedVal(1 + getBytesForLength());
            if (b == 0) return "false";
            if (b == 255) return "true";
            return "0x" + Integer.toString(b, 16);
        }

        public boolean boolValue() {
            return unsignedVal(1 + getBytesForLength()) != 0;
        }

    }

    class INTEGER extends DerValue {
        public INTEGER(DerValue derValue) {
            super(derValue);
        }

        @Override
        protected String printValue() {
            if (valueLength() == 8) {
                return "0x" + Long.toString(longValue(), 16);
            }
            return super.printValue();
        }

        public long longValue() {
            return bytesToLong(valueOffset(), valueLength());
        }
    }

    class BIT_STRING extends DerValue {
        public BIT_STRING(DerValue derValue) {
            super(derValue);
        }
    }

    class OCTET_STRING extends DerCollection {
        public OCTET_STRING(DerValue derValue) {
            super(derValue);
        }
    }

    class OBJECT_IDENTIFIER extends DerValue {
        public OBJECT_IDENTIFIER(DerValue derValue) {
            super(derValue);
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
            int firstTwoNodes = unsignedVal(1 + getBytesForLength());
            StringBuilder value = new StringBuilder(firstTwoNodes / 40 + "." + firstTwoNodes % 40);
            int i = 1;
            while (i< valueLength()) {
                int node = 0;
                int octet;
                do {
                    octet = unsignedVal(1 + getBytesForLength() + i++);
                    node = node << 7 | (octet & ~0x80);
                } while (octet >= 0x80);
                value.append(".").append(node);
            }
            return value.toString();
        }
    }

    class PRINTABLE_STRING extends DerValue {
        public PRINTABLE_STRING(DerValue derValue) {
            super(derValue);
        }

        @Override
        protected String printValue() {
            return "\"" + stringValue() + "\"";
        }

        public String stringValue() {
            return new String(bytes, valueOffset(), valueLength());
        }
    }

    class UTCTime extends DerValue {
        public UTCTime(DerValue derValue) {
            super(derValue);
        }

        @Override
        protected String printValue() {
            return getDateTime().toString();
        }

        public ZonedDateTime getDateTime() {
            String value = new String(bytes, valueOffset(), valueLength());
            String century = value.charAt(0) < '5' ? "20" : "19";
            return ZonedDateTime.parse(century + value, DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"));
        }
    }

    class SEQUENCE extends DerCollection {
        public SEQUENCE(DerValue derValue) {
            super(derValue);
        }

        public Iterator<Der> iterator() {
            return children.iterator();
        }
    }

    class SET extends DerCollection {
        public SET(DerValue derValue) {
            super(derValue);
        }
    }
}
