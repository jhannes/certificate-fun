package io.liquidpki.common;

import io.liquidpki.der.Der;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class X500Name {
    private static final Map<String, Der.OBJECT_IDENTIFIER> RDN_TYPES = Map.of(
            "OU", new Der.OBJECT_IDENTIFIER("2.5.4.11"),
            "O", new Der.OBJECT_IDENTIFIER("2.5.4.10"),
            "CN", new Der.OBJECT_IDENTIFIER("2.5.4.3")
    );
    private static final Map<Der.OBJECT_IDENTIFIER, String> RDN_TYPE_NAMES = RDN_TYPES.entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));



    private Der der;
    protected List<AttributeTypeAndValue> rdnSequence = new ArrayList<>();

    public X500Name(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        while (iterator.hasNext()) {
            Der.SET relativeDistinquishedName = (Der.SET) iterator.next();
            rdnSequence.add(new AttributeTypeAndValue(relativeDistinquishedName.first()));
        }
    }

    public X500Name() {

    }

    public X500Name(String distingishedName) {
        try {
            LdapName ldapName = new LdapName(distingishedName);
            List<Rdn> rdns = ldapName.getRdns();
            for (Rdn rdn : rdns) {
                rdn(rdn);
            }
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public void rdn(Rdn rdn) {
        Der.OBJECT_IDENTIFIER type = RDN_TYPES.get(rdn.getType());
        if (type == null) {
            throw new IllegalArgumentException("Unknown DN type name " + rdn.getType());
        }
        rdnSequence.add(new AttributeTypeAndValue(type, rdn.getValue().toString()));
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
        rdnSequence.forEach(a -> a.dump(out, indent + "  "));
    }

    public X500Name cn(String commonName) {
        return attribute("2.5.4.3", commonName);
    }

    public X500Name o(String organization) {
        return attribute("2.5.4.10", organization);
    }

    public X500Name ou(String organizationUnit) {
        return attribute("2.5.4.11", organizationUnit);
    }

    public String cn() {
        return attribute("2.5.4.3");
    }

    public String o() {
        return attribute("2.5.4.10");
    }

    public String ou() {
        return attribute("2.5.4.11");
    }

    public String attribute(String oid) {
        return rdnSequence.stream()
                .filter(a -> a.type.getObjectIdentifier().equals(oid))
                .findFirst()
                .map(a -> a.value.stringValue())
                .orElse(null);
    }


    public X500Name attribute(String oid, String value) {
        rdnSequence.add(new AttributeTypeAndValue(oid, value));
        return this;
    }

    public Der toDer() {
        List<Der> contents = rdnSequence.stream()
                .map(attributeTypeAndValue -> new Der.SET(List.of(attributeTypeAndValue.toDer())))
                .collect(Collectors.toList());
        return new Der.SEQUENCE(contents);
    }

    public String print() {
        List<AttributeTypeAndValue> rdnSequence = new ArrayList<>(this.rdnSequence);
        Collections.reverse(rdnSequence);
        return rdnSequence.stream()
                .map(entry -> RDN_TYPE_NAMES.get(entry.type) + "=" + entry.value.stringValue())
                .collect(Collectors.joining(","));
    }

    public static class AttributeTypeAndValue {
        protected final Der.OBJECT_IDENTIFIER type;
        protected final Der.DerString value;

        public AttributeTypeAndValue(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            type = (Der.OBJECT_IDENTIFIER)iterator.next();
            value = (Der.DerString)iterator.next(); // inexact - can be Telex, Universal, UTF8, BMP
        }

        public AttributeTypeAndValue(String type, String value) {
            this(new Der.OBJECT_IDENTIFIER(type), value);
        }

        public AttributeTypeAndValue(Der.OBJECT_IDENTIFIER type, String value) {
            this.type = type;
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
