package io.liquidpki.pkcs10;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.common.X501Name;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** https://tools.ietf.org/html/rfc2986 */
public class CertificationRequest {

    private Der der;
    protected final CertificationRequestInfo certificationRequestInfo;
    protected final AlgorithmIdentifier signatureAlgorithm;
    protected final Der.BIT_STRING signature;

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

    public static class CertificationRequestInfo {
        private Der der;
        protected final Der.INTEGER version;
        protected final X501Name subject;
        protected final SubjectPublicKeyInfo subjectPKInfo;
        protected final CRIAttributes attributes;

        public CertificationRequestInfo(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            version = (Der.INTEGER)iterator.next();
            subject = new X501Name(iterator.next());
            subjectPKInfo = new SubjectPublicKeyInfo(iterator.next());
            attributes = iterator.hasNext() ? new CRIAttributes(iterator.next()) : null;
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
            out.println(indent + "  version=" + version.longValue());
            subject.dump(out, "subject", indent + "  ", debug);
            subjectPKInfo.dump(out, "subjectPKInfo", indent + "  ", debug);
            attributes.dump(out, "attributes", indent + "  ", debug);
        }
    }

    public static class CRIAttributes {
        private Der der;
        protected final Der.OBJECT_IDENTIFIER type;
        protected List<Extension> values = new ArrayList<>();

        public CRIAttributes(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) ((DerCollection) der).first()).iterator();
            type = (Der.OBJECT_IDENTIFIER) iterator.next();
            Iterator<Der> valuesIterator = ((Der.SEQUENCE) (((Der.SET) iterator.next()).first())).iterator();
            while (valuesIterator.hasNext()) {
                values.add(new Extension(valuesIterator.next()));
            }
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ": " + type.getName() + (debug ? " " + der : ""));
            values.forEach(a -> a.dump(out, indent + "  ", debug));
        }
    }

    public void dump(PrintStream out, boolean debug) {
        out.println("CertificationRequest:" + (debug ? " " + der : ""));
        certificationRequestInfo.dump(out, "certificationRequestInfo", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signature" + "=" + signature.describeValue() + " [length=" + signature.valueLength() + "]");
    }
}
