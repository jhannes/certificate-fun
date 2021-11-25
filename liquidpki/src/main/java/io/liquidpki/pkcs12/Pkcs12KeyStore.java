package io.liquidpki.pkcs12;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.Iterator;

/**
 * https://datatracker.ietf.org/doc/html/rfc7292#section-4
 */
public class Pkcs12KeyStore {
    private final Der.INTEGER version;
    private final ContentInfo authSafe;
    private final MacData macData;
    private final Der der;

    public Pkcs12KeyStore(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        version = (Der.INTEGER) iterator.next();
        authSafe = new ContentInfo((Der.SEQUENCE) iterator.next());
        macData = iterator.hasNext() ? new MacData((Der.SEQUENCE) iterator.next()) : null;
    }

    public void output(PrintStream out, String indent) {
        der.output(out, indent);
        out.println(getClass().getSimpleName() + ": " + der);
        out.println(indent + "  version=" + version);
        authSafe.output(out, indent + "  ");
        if (macData != null) {
            macData.output(out, indent + "  ");
        }
    }
}
