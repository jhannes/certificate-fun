package io.liquidpki.pkcs12;

import io.liquidpki.der.Der;

import java.io.PrintStream;

public class MacData {
    private Der.SEQUENCE der;

    public MacData(Der.SEQUENCE der) {
        this.der = der;
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + getClass().getSimpleName() + ": " + der);
    }
}
