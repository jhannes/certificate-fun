package io.liquidpki.der;

public class DerContextSpecificValue extends DerCollection {
    public DerContextSpecificValue(DerValue derValue) {
        super(derValue);
    }

    public String stringValue() {
        return new String(bytes, valueOffset(), valueLength());
    }
}
