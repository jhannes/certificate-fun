package io.liquidpki.x509;

import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.x501.X501Name;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static io.liquidpki.der.ExamineCertificate.readPemObjects;

/**
 * As defined by https://tools.ietf.org/html/rfc5280
 */
public class X509Certificate {

    private Der der;

    private static class TbsCertificate {
        private final CertificateVersion version;
        private final Der.INTEGER serialNumber;
        private final AlgorithmIdentifier signature;
        private final X501Name issuer;
        private final Validity validity;
        private final X501Name subject;
        private final SubjectPublicKeyInfo subjectPublicKeyInfo;
        private final CertificateExtensions extensions;
        private Der der;

        public TbsCertificate(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            version = new CertificateVersion(iterator.next());
            serialNumber = (Der.INTEGER)iterator.next();
            signature = new AlgorithmIdentifier(iterator.next());
            issuer = new X501Name(iterator.next());
            validity = new Validity(iterator.next());
            subject = new X501Name(iterator.next());
            subjectPublicKeyInfo = new SubjectPublicKeyInfo(iterator.next());
            extensions = new CertificateExtensions(iterator.next());
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
            version.dump(out, "version", indent + "  ", debug);
            out.println(indent + "  serialNumber=" + serialNumber.longValue());
            signature.dump(out, "signature", indent + "  ", debug);
            issuer.dump(out, "issuer", indent + "  ", debug);
            validity.dump(out, "validity", indent + "  ");
            subject.dump(out, "subject", indent + "  ", debug);
            subjectPublicKeyInfo.dump(out, "subjectPublicKeyInfo", indent + "  ", debug);
            extensions.dump(out, "extensions", indent + "  ", debug);
        }
    }

    private static class AlgorithmIdentifier {
        private Der der;
        private Der.OBJECT_IDENTIFIER algorithm;
        private final Der parameters;

        public AlgorithmIdentifier(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            this.algorithm = (Der.OBJECT_IDENTIFIER) iterator.next();
            this.parameters = iterator.hasNext() ? iterator.next() : null;
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + "=" + algorithm.getName() + " " + parameters + (debug ? " " + der : ""));
        }
    }

    private static class CertificateVersion {
        private Der der;
        private final Der.INTEGER version;

        public CertificateVersion(Der der) {
            this.der = der;
            this.version = ((Der.INTEGER) ((DerCollection) der).first());
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ": " + version.longValue() + (debug ? " " + der : ""));
        }
    }

    private static class Validity {
        private Der der;
        private final Der.UTCTime notBefore;
        private final Der.UTCTime notAfter;

        public Validity(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            this.notBefore = (Der.UTCTime)iterator.next(); // Inexact - should be DerTimestamp of either UTCTime or GeneralizedTime
            this.notAfter = (Der.UTCTime)iterator.next();
        }

        public void dump(PrintStream out, String fieldName, String indent) {
            out.println(indent + fieldName + "=" + notBefore.getDateTime() + " to " + notAfter.getDateTime());
        }
    }

    private static class SubjectPublicKeyInfo {
        private Der der;
        private final Der.OBJECT_IDENTIFIER algorithm;
        private final Der.BIT_STRING subjectPublicKey;

        public SubjectPublicKeyInfo(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            this.algorithm = (Der.OBJECT_IDENTIFIER)((Der.SEQUENCE)iterator.next()).first();
            this.subjectPublicKey = (Der.BIT_STRING) iterator.next();
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + "=" + algorithm.getObjectIdentifier() + " " + subjectPublicKey.describeValue() + (debug ? " " + der : ""));
        }
    }

    private static class CertificateExtensions {
        private Der der;
        private List<Extension> extensions = new ArrayList<>();

        public CertificateExtensions(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) ((DerCollection) der).first()).iterator();
            while (iterator.hasNext()) {
                extensions.add(new Extension(iterator.next()));
            }
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ":" + (debug ? " " + der : ""));
            extensions.forEach(e -> e.dump(out, indent + "  "));
        }
    }

    private static class Extension {
        private Der der;
        private final Der.OBJECT_IDENTIFIER extnId;
        private final Der.BOOLEAN critical;
        private final Der.OCTET_STRING extnValue;

        public Extension(Der der) {
            this.der = der;
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            extnId = (Der.OBJECT_IDENTIFIER)iterator.next();
            Der next = iterator.next();
            if (next instanceof Der.BOOLEAN) {
                critical = (Der.BOOLEAN) next;
                extnValue = (Der.OCTET_STRING)iterator.next();
            } else {
                critical = null;
                extnValue = (Der.OCTET_STRING)next;
            }
        }

        public void dump(PrintStream out, String indent) {
            out.println(indent + extnId.getName() + (critical != null ? " critical=" + critical.boolValue() : "") + " " + extnValue.describeValue());
        }
    }

    private final TbsCertificate tbsCertificate;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final Der.BIT_STRING signatureValue;

    public X509Certificate(byte[] derBytes) {
        this(Der.parse(derBytes));
    }

    public X509Certificate(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        this.tbsCertificate = new TbsCertificate(iterator.next());
        this.signatureAlgorithm = new AlgorithmIdentifier(iterator.next());
        this.signatureValue = (Der.BIT_STRING)iterator.next();
    }

    private void dump(PrintStream out, boolean debug) {
        out.println("X509Certificate:" + (debug ? " " + der : ""));
        tbsCertificate.dump(out, "tbsCertificate", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signatureValue" + "=" + signatureValue);
    }

    public static void main(String[] args) throws IOException {
        ByteArrayOutputStream buffer;
        try (InputStream input = new FileInputStream("local-test-certificate.crt")) {
            buffer = new ByteArrayOutputStream();
            input.transferTo(buffer);
        }

        for (byte[] derBytes : readPemObjects(buffer)) {
            new X509Certificate(derBytes).dump(System.out, false);
        }
    }
}
