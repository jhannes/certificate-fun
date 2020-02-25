package io.liquidpki.der;

import java.io.PrintStream;
import java.nio.charset.Charset;

public class DerContextSpecificValue extends DerValue {

    public DerContextSpecificValue(DerValue derValue) {
        super(derValue);
    }

    public DerContextSpecificValue(int tag, byte[] value) {
        super(tag, value);
    }

    public String stringValue() {
        return stringValue(Charset.defaultCharset());
    }

    public Der parse() {
        return Der.parse(atOffset(0));
    }

    @Override
    public void output(PrintStream out, String indent) {
        super.output(out, indent);
        Der child = parse();
        if (child.fullLength() == this.valueLength()) {
            child.output(out, "  " + indent);
        }
    }
}
