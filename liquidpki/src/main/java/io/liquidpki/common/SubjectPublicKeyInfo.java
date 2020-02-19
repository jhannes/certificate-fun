package io.liquidpki.common;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.Iterator;

public class SubjectPublicKeyInfo {
    private Der der;
    protected final Der.OBJECT_IDENTIFIER algorithm;
    protected final Der.BIT_STRING subjectPublicKey;

    public SubjectPublicKeyInfo(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        this.algorithm = (Der.OBJECT_IDENTIFIER)((Der.SEQUENCE)iterator.next()).first();
        this.subjectPublicKey = (Der.BIT_STRING) iterator.next();
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + "=" + algorithm.getName() + " " + subjectPublicKey.describeValue() + " [length: " + subjectPublicKey.valueLength() + "]" + (debug ? " " + der : ""));
    }
}
