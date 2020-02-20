package io.liquidpki.der;

public class DerContextSpecificValue extends DerCollection {
    private final String stringValue;

    public DerContextSpecificValue(DerValue derValue) {
        super(derValue);
        this.stringValue = new String(derValue.bytes, derValue.valueOffset(), derValue.valueLength());
    }

    public String stringValue() {
        return stringValue;
    }
}
