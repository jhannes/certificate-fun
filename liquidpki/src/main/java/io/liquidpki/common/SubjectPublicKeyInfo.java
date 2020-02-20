package io.liquidpki.common;

import io.liquidpki.der.Der;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;

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

    public SubjectPublicKeyInfo(PublicKey publicKey) {
        algorithm = new Der.OBJECT_IDENTIFIER(Oid.getSignatureAlgorithm(publicKey.getAlgorithm()));
        subjectPublicKey = new Der.BIT_STRING(publicKey.getEncoded());
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + "=" + algorithm.getName() + " " + subjectPublicKey.describeValue() + " [length: " + subjectPublicKey.valueLength() + "]" + (debug ? " " + der : ""));
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(new Der.SEQUENCE(List.of(algorithm)), subjectPublicKey));
    }
}
