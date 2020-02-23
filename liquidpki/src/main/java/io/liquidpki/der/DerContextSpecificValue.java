package io.liquidpki.der;

public class DerContextSpecificValue extends DerValue {

    public DerContextSpecificValue(DerValue derValue) {
        super(derValue);
    }

    public DerContextSpecificValue(int tag, byte[] value) {
        super(tag, value);
    }

    public String stringValue() {
        return new String(bytes, valueOffset(), valueLength());
    }

    public Der parse() {
        return Der.parse(atOffset(1 + getBytesForLength()));
    }
}
