package io.liquidpki.common;

import io.liquidpki.der.Der;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

public class CertificateExtensions {
    private Der der;
    protected List<Extension> extensions = new ArrayList<>();

    public CertificateExtensions(Der.SEQUENCE der) {
        this.der = der;
        Iterator<Der> iterator = der.iterator();
        while (iterator.hasNext()) {
            extensions.add(new Extension(iterator.next()));
        }
    }

    public CertificateExtensions() {

    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
        extensions.forEach(e -> e.dump(out, indent + "  ", debug));
    }

    public Der.SEQUENCE toDer() {
        return new Der.SEQUENCE(extensions.stream().map(Extension::toDer).collect(Collectors.toList()));
    }

    public void add(Extension.ExtensionType extension) {
        this.extensions.add(new Extension(extension));
    }

    public Extension.SANExtensionType sanExtension() {
        return extension(Extension.SANExtensionType.class);
    }

    public Extension.KeyUsageExtensionType keyUsage() {
        return extension(Extension.KeyUsageExtensionType.class);
    }

    private <T> T extension(Class<T> extensionType) {
        //noinspection unchecked
        return (T) extensions.stream()
                .map(Extension::getExtensionType)
                .filter(e -> e.getClass() == extensionType)
                .findFirst()
                .orElse(null);
    }

    public boolean isEmpty() {
        return extensions.isEmpty();
    }
}
