package io.liquidpki.der;

import java.util.List;

public class DerContextSpecificValue extends DerCollection {
    private String stringValue;

    public DerContextSpecificValue(DerValue derValue) {
        super(derValue);
        this.stringValue = new String(derValue.bytes, derValue.valueOffset(), derValue.valueLength());
    }

    public DerContextSpecificValue(int tag, List<Der> children) {
        super(tag, children);
    }

    public String stringValue() {
        return stringValue;
    }
}
