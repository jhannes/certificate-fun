package io.liquidpki.pkcs10;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.der.ExamineCertificate;
import io.liquidpki.x501.X501Name;

import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** https://tools.ietf.org/html/rfc2986 */
public class CertificationRequest {

    public static void main(String[] args) throws IOException {
        for (byte[] derBytes : ExamineCertificate.readPemObjects("local-test-request.csr")) {
            new CertificationRequest(derBytes).dump(System.out, false);
        }
    }


    private Der der;
    private final CertificationRequestInfo certificationRequestInfo;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final Der.BIT_STRING signature;

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

    private void dump(PrintStream out, boolean debug) {
        out.println("CertificationRequest:" + (debug ? " " + der : ""));
        certificationRequestInfo.dump(out, "certificationRequestInfo", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signature" + "=" + signature.describeValue() + " [length=" + signature.valueLength() + "]");
    }

    private static class CertificationRequestInfo {
        private Der der;
        private final Der.INTEGER version;
        private final X501Name subject;
        private final SubjectPublicKeyInfo subjectPKInfo;
        private final CRIAttributes attributes;

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

    private static class CRIAttributes {
        private Der der;
        private final Der.OBJECT_IDENTIFIER type;
        private List<Extension> values = new ArrayList<>();

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
}
