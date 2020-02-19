package io.liquidpki.x501;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class X501Name {
    private Der der;
    protected List<AttributeTypeAndValue> rdnSequence = new ArrayList<>();

    public X501Name(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        while (iterator.hasNext()) {
            Der.SET relativeDistinquishedName = (Der.SET) iterator.next();
            rdnSequence.add(new AttributeTypeAndValue(relativeDistinquishedName.first()));
        }
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
        rdnSequence.forEach(a -> a.dump(out, indent + "  "));
    }

    public static class AttributeTypeAndValue {
        protected final Der.OBJECT_IDENTIFIER type;
        protected final Der.PRINTABLE_STRING value;

        public AttributeTypeAndValue(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            type = (Der.OBJECT_IDENTIFIER)iterator.next();
            value = (Der.PRINTABLE_STRING)iterator.next(); // inexact - can be Telex, Universal, UTF8, BMP
        }

        public void dump(PrintStream out, String indent) {
            out.println(indent + type.getName() + "=" + value.stringValue());
        }
    }
}
