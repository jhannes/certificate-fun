package io.liquidpki.pkcs10;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.CertificateExtensions;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.common.X500Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.der.DerValue;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CertificationRequestInfo {
    protected Der.INTEGER version;
    protected X500Name subject;
    protected SubjectPublicKeyInfo subjectPKInfo;
    protected final CRIAttributes attributes;

    public CertificationRequestInfo(Der der) {
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        version = (Der.INTEGER) iterator.next();
        subject = new X500Name(iterator.next());
        subjectPKInfo = new SubjectPublicKeyInfo(iterator.next());
        attributes = iterator.hasNext() ? new CRIAttributes(iterator.next()) : new CRIAttributes();
    }

    public CertificationRequestInfo() {
        version = new Der.INTEGER(0);
        subject = new X500Name();
        subjectPKInfo = null;
        attributes = new CRIAttributes();
    }

    public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
        out.println(indent + fieldName + ":");
        out.println(indent + "  version=" + version.longValue());
        subject.dump(out, "subject", indent + "  ", debug);
        subjectPKInfo.dump(out, "subjectPKInfo", indent + "  ", debug);
        attributes.dump(out, "attributes", indent + "  ", debug);
    }

    public CertificationRequestInfo version(int version) {
        this.version = new Der.INTEGER(version);
        return this;
    }

    public CertificationRequestInfo subject(X500Name subject) {
        this.subject = subject;
        return this;
    }

    public CertificationRequestInfo publicKey(PublicKey publicKey) {
        this.subjectPKInfo = new SubjectPublicKeyInfo((RSAPublicKey) publicKey);
        return this;
    }

    public CertificationRequestInfo addExtension(Extension.ExtensionType extensionType) {
        attributes.addExtension(extensionType);
        return this;
    }

    public Der toDer() {
        if (attributes.isEmpty()) {
            return new Der.SEQUENCE(List.of(version, subject.toDer(), subjectPKInfo.toDer(), attributes.toDer()));
        } else {
            return new Der.SEQUENCE(List.of(version, subject.toDer(), subjectPKInfo.toDer()));
        }
    }

    public X500Name subject() {
        return subject;
    }

    public RSAPublicKey publicKey() throws GeneralSecurityException {
        return subjectPKInfo.getPublicKey();
    }

    public CertificateExtensions extensions() {
        return attributes.extensions;
    }

    public CertificationRequest signWithKey(PrivateKey privateKey) throws GeneralSecurityException {
        return new CertificationRequest(this, new AlgorithmIdentifier(Oid.getPublicKeyAlgorithm(privateKey.getAlgorithm())), signature(privateKey));
    }

    public byte[] signature(PrivateKey privateKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        byte[] bytes = toDer().toByteArray();
        signature.update(bytes, 0, bytes.length);
        return signature.sign();
    }

    public static class CRIAttributes {
        private List<CRIAttribute> attributes = new ArrayList<>();
        private CertificateExtensions extensions = new CertificateExtensions();

        public CRIAttributes(Der der) {
            Iterator<Der> iterator = new DerCollection((DerValue) der).iterator();
            while (iterator.hasNext()) {
                CRIAttribute attribute = new CRIAttribute(iterator.next());
                if (attribute.type.getObjectIdentifier().equals("1.2.840.113549.1.9.14")) {
                    extensions = new CertificateExtensions((Der.SEQUENCE) attribute.value.first());
                } else {
                    attributes.add(attribute);
                }
            }
        }

        public CRIAttributes() {
        }

        public Der toDer() {
            List<Der> attributesDer = new ArrayList<>();
            attributes.stream().map(CRIAttribute::toDer).forEach(attributesDer::add);
            if (!extensions.isEmpty()) {
                attributesDer.add(new CRIAttribute("1.2.840.113549.1.9.14", new Der.SET(extensions.toDer().toByteArray())).toDer());
            }
            return new DerCollection(0xA0, attributesDer);
        }

        public boolean isEmpty() {
            return attributes.isEmpty();
        }

        public void addExtension(Extension.ExtensionType extensionType) {
            this.extensions.add(extensionType);
        }

        public void dump(PrintStream out, String attributes, String s, boolean debug) {
        }
    }

    private static class CRIAttribute {
        private final Der.OBJECT_IDENTIFIER type;
        private final Der.SET value;

        public CRIAttribute(String oid, Der.SET value) {
            this.type = new Der.OBJECT_IDENTIFIER(oid);
            this.value = value;
        }

        public CRIAttribute(Der next) {
            Iterator<Der> iterator = ((Der.SEQUENCE) next).iterator();
            type = (Der.OBJECT_IDENTIFIER) iterator.next();
            value = (Der.SET) iterator.next();
        }

        public Der toDer() {
            return new Der.SEQUENCE(List.of(type, value));
        }
    }
}
