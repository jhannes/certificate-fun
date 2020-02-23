package io.liquidpki.pkcs10;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.CertificateExtensions;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.common.X501Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.der.DerValue;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** https://tools.ietf.org/html/rfc2986 */
public class CertificationRequest {

    private Der der;
    protected CertificationRequestInfo certificationRequestInfo;
    protected AlgorithmIdentifier signatureAlgorithm;
    protected Der.BIT_STRING signature;

    public CertificationRequest(byte[] derBytes) {
        this(Der.parse(derBytes));
    }

    public CertificationRequest(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        certificationRequestInfo = new CertificationRequestInfo(iterator.next());
        signatureAlgorithm = new AlgorithmIdentifier(iterator.next());
        signature = (Der.BIT_STRING) iterator.next();
    }

    public CertificationRequest() {
        certificationRequestInfo = new CertificationRequestInfo();
        signatureAlgorithm = null;
        signature = null;
    }

    public CertificationRequest info(CertificationRequestInfo certificationRequestInfo) {
        this.certificationRequestInfo = certificationRequestInfo;
        return this;
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(certificationRequestInfo.toDer(), signatureAlgorithm.toDer(), signature));
    }

    public CertificationRequest signWithKey(PrivateKey privateKey) throws GeneralSecurityException {
        this.signatureAlgorithm = new AlgorithmIdentifier(Oid.getPublicKeyAlgorithm(privateKey.getAlgorithm()));
        byte[] bytes = certificationRequestInfo.toDer().toByteArray();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(bytes, 0, bytes.length);
        byte[] sign = signature.sign();
        this.signature = new Der.BIT_STRING(sign);
        return this;
    }

    public static class CertificationRequestInfo {
        protected Der.INTEGER version;
        protected X501Name subject;
        protected SubjectPublicKeyInfo subjectPKInfo;
        protected final CRIAttributes attributes;

        public CertificationRequestInfo(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            version = (Der.INTEGER)iterator.next();
            subject = new X501Name(iterator.next());
            subjectPKInfo = new SubjectPublicKeyInfo(iterator.next());
            attributes = iterator.hasNext() ? new CRIAttributes(iterator.next()) : new CRIAttributes();
        }

        public CertificationRequestInfo() {
            version = new Der.INTEGER(0);
            subject = new X501Name();
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

        public CertificationRequestInfo subject(X501Name subject) {
            this.subject = subject;
            return this;
        }

        public CertificationRequestInfo publicKey(RSAPublicKey publicKey) {
            this.subjectPKInfo = new SubjectPublicKeyInfo(publicKey);
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

        public X501Name subject() {
            return subject;
        }

        public RSAPublicKey publicKey() throws GeneralSecurityException {
            return subjectPKInfo.getPublicKey();
        }

        public CertificateExtensions extensions() {
            return attributes.extensions;
        }
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

    public void dump(PrintStream out, boolean debug) {
        out.println("CertificationRequest:" + (debug ? " " + der : ""));
        certificationRequestInfo.dump(out, "certificationRequestInfo", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signature" + "=" + signature.describeValue() + " [length=" + signature.valueLength() + "]");
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
