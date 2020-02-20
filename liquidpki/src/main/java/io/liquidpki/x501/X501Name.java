package io.liquidpki.x501;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

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

    public X501Name() {

    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
        rdnSequence.forEach(a -> a.dump(out, indent + "  "));
    }

    public X501Name cn(String commonName) {
        return attribute("2.5.4.3", commonName);
    }

    public X501Name o(String organization) {
        return attribute("2.5.4.10", organization);
    }
    private X501Name attribute(String oid, String value) {
        rdnSequence.add(new AttributeTypeAndValue(oid, value));
        return this;
    }

    public Der toDer() {
        List<Der> contents = rdnSequence.stream().map(AttributeTypeAndValue::toDer).collect(Collectors.toList());
        return new Der.SEQUENCE(contents);
    }

    public static class AttributeTypeAndValue {
        protected final Der.OBJECT_IDENTIFIER type;
        protected final Der.PRINTABLE_STRING value;

        public AttributeTypeAndValue(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            type = (Der.OBJECT_IDENTIFIER)iterator.next();
            value = (Der.PRINTABLE_STRING)iterator.next(); // inexact - can be Telex, Universal, UTF8, BMP
        }

        public AttributeTypeAndValue(String type, String value) {
            this.type = new Der.OBJECT_IDENTIFIER(type);
            this.value = new Der.PRINTABLE_STRING(value);
        }

        public void dump(PrintStream out, String indent) {
            out.println(indent + type.getName() + "=" + value.stringValue());
        }

        public Der toDer() {
            return new Der.SEQUENCE(List.of(type, value));
        }
    }
}
