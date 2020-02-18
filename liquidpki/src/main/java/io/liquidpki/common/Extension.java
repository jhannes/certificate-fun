package io.liquidpki.common;

import io.liquidpki.der.Der;
import io.liquidpki.der.DerContextSpecificValue;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class Extension {
    private static Map<String, Function<Der.OCTET_STRING, ExtensionType>> factory = Map.of(
            "2.5.29.15", KeyUsageExtensionType::new,
            "2.5.29.17", SANExtensionType::new,
            "2.5.29.19", BasicConstraintExtensionType::new
    );

    private Der der;
    private final Der.OBJECT_IDENTIFIER extnId;
    private final Der.BOOLEAN critical;
    private final ExtensionType extensionType;

    public Extension(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        extnId = (Der.OBJECT_IDENTIFIER)iterator.next();
        Der next = iterator.next();
        Der.OCTET_STRING extnValue;
        if (next instanceof Der.BOOLEAN) {
            critical = (Der.BOOLEAN) next;
            extnValue = (Der.OCTET_STRING)iterator.next();
        } else {
            critical = null;
            extnValue = (Der.OCTET_STRING)next;
        }
        extensionType = factory.getOrDefault(extnId.getObjectIdentifier(), UnknownExtensionType::new).apply(extnValue);
    }

    public void dump(PrintStream out, String indent, boolean debug) {
        out.println(indent + extnId.getName() + (critical != null ? " critical=" + critical.boolValue() : "") + " " + (debug ? " " + der : ""));
        extensionType.dump(out, indent + "  ");
    }

    private interface ExtensionType {
        void dump(PrintStream out, String indent);
    }

    private static class SANExtensionType implements ExtensionType {
        private static Map<Integer, String> NAME_TYPE = Map.of(
                0x80, "otherName",
                0x81, "rfc822Name",
                0x82, "dNSName",
                0x83, "x400Address",
                0x84, "directoryName",
                0x85, "ediPartyName",
                0x86, "uniformResourceIdentifier",
                0x87, "IPAddress",
                0x88, "registeredID"
        );

        private List<DerContextSpecificValue> generalNames = new ArrayList<>();

        public SANExtensionType(Der.OCTET_STRING der) {
            Iterator<Der> iterator = ((Der.SEQUENCE)Der.parse(der.byteArray())).iterator();
            while (iterator.hasNext()) {
                generalNames.add((DerContextSpecificValue) iterator.next());
            }
        }

        @Override
        public void dump(PrintStream out, String indent) {
            out.println(indent + "SubjectAlternativeName");
            generalNames.forEach(der ->
                    out.println(indent + "  " + NAME_TYPE.getOrDefault(der.getTag(), "unknown") + " " + der.stringValue()));
        }
    }

    private static class KeyUsageExtensionType implements ExtensionType {
        private Map<Integer, String> USAGE_NAME = Map.of(
                0b10000000, "digitalSignature",
                0b01000000, "nonRepudiation",
                0b00100000, "keyEncipherment",
                0b00010000, "dataEncipherment",
                0b00001000, "keyAgreement",
                0b00000100, "keyCertSign",
                0b00000010, "cRLSign"
        );

        private final Der.BIT_STRING keyUsage;

        public KeyUsageExtensionType(Der.OCTET_STRING der) {
            this.keyUsage = (Der.BIT_STRING)Der.parse(der.byteArray());
        }

        @Override
        public void dump(PrintStream out, String indent) {
            out.println(indent + "Key Usage");
            USAGE_NAME.forEach((k, v) -> {
                if ((k & keyUsage.longValue()) != 0) out.println(indent + "  " + v);
            });
        }
    }

    private static class BasicConstraintExtensionType implements ExtensionType {

        private final Der.BOOLEAN ca;
        private final Der.INTEGER pathLengthConstraint;

        public BasicConstraintExtensionType(Der.OCTET_STRING der) {
            Iterator<Der> iterator = ((Der.SEQUENCE)Der.parse(der.byteArray())).iterator();
            ca = (Der.BOOLEAN)iterator.next();
            if (iterator.hasNext()) {
                pathLengthConstraint = (Der.INTEGER)iterator.next();
            } else {
                pathLengthConstraint = null;
            }
        }

        @Override
        public void dump(PrintStream out, String indent) {
            out.println(indent + "KeyUsage: ca=" + ca.boolValue() +
                    (pathLengthConstraint != null ? " pathLengthConstraint=" + pathLengthConstraint.longValue() : ""));
        }
    }

    private static class UnknownExtensionType implements ExtensionType {

        private final Der.OCTET_STRING der;

        public UnknownExtensionType(Der.OCTET_STRING der) {
            this.der = der;
        }

        @Override
        public void dump(PrintStream out, String indent) {
            der.output(out, indent);
        }
    }
}
