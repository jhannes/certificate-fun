package io.liquidpki.common;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.Iterator;

public class AlgorithmIdentifier {
    private Der der;
    protected Der.OBJECT_IDENTIFIER algorithm;
    protected final Der parameters;

    public AlgorithmIdentifier(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        this.algorithm = (Der.OBJECT_IDENTIFIER) iterator.next();
        this.parameters = iterator.hasNext() ? iterator.next() : null;
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + "=" + algorithm.getName() + " " + parameters + (debug ? " " + der : ""));
    }
}
