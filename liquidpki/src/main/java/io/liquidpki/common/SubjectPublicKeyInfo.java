package io.liquidpki.common;

import io.liquidpki.der.Der;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import java.util.List;

public class SubjectPublicKeyInfo {
    private Der der;
    protected final Der.OBJECT_IDENTIFIER algorithm;
    protected final Der.BIT_STRING subjectPublicKey;
    private final BigInteger modulus;
    private BigInteger exponent;

    public SubjectPublicKeyInfo(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        this.algorithm = (Der.OBJECT_IDENTIFIER)((Der.SEQUENCE)iterator.next()).first();
        this.subjectPublicKey = (Der.BIT_STRING) iterator.next();

        Iterator<Der> keyIterator = ((Der.SEQUENCE) subjectPublicKey.parse()).iterator();
        this.modulus = ((Der.INTEGER)keyIterator.next()).toBigInteger();
        this.exponent = ((Der.INTEGER)keyIterator.next()).toBigInteger();
    }

    public SubjectPublicKeyInfo(RSAPublicKey publicKey) {
        algorithm = new Der.OBJECT_IDENTIFIER(Oid.getSignatureAlgorithm(publicKey.getAlgorithm()));
        modulus = publicKey.getModulus();
        exponent = publicKey.getPublicExponent();
        subjectPublicKey = new Der.BIT_STRING(new Der.SEQUENCE(List.of(
                new Der.INTEGER(modulus),
                new Der.INTEGER(exponent)
        )).toByteArray());
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + "=" + algorithm.getName() + " " + subjectPublicKey.describeValue() + " [length: " + subjectPublicKey.valueLength() + "]" + (debug ? " " + der : ""));
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(new Der.SEQUENCE(List.of(algorithm, new Der.NULL())), subjectPublicKey));
    }

    public RSAPublicKey getPublicKey() throws GeneralSecurityException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(spec);
    }
}
