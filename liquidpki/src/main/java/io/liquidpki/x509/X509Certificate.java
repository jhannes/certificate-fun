package io.liquidpki.x509;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.common.X501Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerContextSpecificValue;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * As defined by https://tools.ietf.org/html/rfc5280
 */
public class X509Certificate {

    private Der der;
    protected TbsCertificate tbsCertificate;
    protected AlgorithmIdentifier signatureAlgorithm;
    protected Der.BIT_STRING signatureValue;

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

    public X509Certificate() {
        tbsCertificate = new TbsCertificate();
        signatureAlgorithm = null;
        signatureValue = new Der.BIT_STRING(new byte[0]);
    }

    public X509Certificate tbsCertificate(TbsCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
        return this;
    }

    public X509Certificate signWithKey(PrivateKey privateKey) throws GeneralSecurityException {
        signatureAlgorithm(privateKey);
        byte[] bytes = tbsCertificate.toDer().toByteArray();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(bytes, 0, bytes.length);
        byte[] sign = signature.sign();
        signatureValue = new Der.BIT_STRING(sign);
        return this;
    }

    public X509Certificate signatureAlgorithm(PrivateKey privateKey) {
        this.signatureAlgorithm = new AlgorithmIdentifier(Oid.getPublicKeyAlgorithm(privateKey.getAlgorithm()));
        tbsCertificate.signature(Oid.getPublicKeyAlgorithm(privateKey.getAlgorithm()));
        return this;
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(tbsCertificate.toDer(), signatureAlgorithm.toDer(), signatureValue));
    }

    public static class TbsCertificate {
        protected CertificateVersion version;
        protected Der.INTEGER serialNumber;
        protected AlgorithmIdentifier signature; // nullable
        protected X501Name issuer;
        protected Validity validity;
        protected X501Name subject;
        protected SubjectPublicKeyInfo subjectPublicKeyInfo; // nullable
        protected CertificateExtensions extensions;
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

        public TbsCertificate() {
            version = new CertificateVersion(3);
            serialNumber = new Der.INTEGER(1);
            signature = null;
            issuer = new X501Name();
            validity = new Validity(ZonedDateTime.now(), ZonedDateTime.now().plusMonths(6));
            subject = new X501Name();
            subjectPublicKeyInfo = null;
            extensions = null;
        }

        public Der toDer() {
            return new Der.SEQUENCE(List.of(
                    version.toDer(),
                    serialNumber,
                    signature.toDer(),
                    issuer.toDer(),
                    validity.toDer(),
                    subject.toDer(),
                    subjectPublicKeyInfo.toDer(),
                    extensions.toDer()
            ));
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

        public TbsCertificate version(int version) {
            this.version = new CertificateVersion(version);
            return this;
        }

        public int version() {
            return (int)this.version.version.longValue();
        }

        public TbsCertificate serialNumber(long serialNumber) {
            this.serialNumber = new Der.INTEGER(serialNumber);
            return this;
        }

        public TbsCertificate signature(String signatureAlgorithm) {
            this.signature = new AlgorithmIdentifier(signatureAlgorithm);
            return this;
        }

        public TbsCertificate issuerName(X501Name issuer) {
            this.issuer = issuer;
            return this;
        }

        public TbsCertificate validity(ZonedDateTime notBefore, ZonedDateTime notAfter) {
            this.validity = new Validity(notBefore, notAfter);
            return this;
        }

        public TbsCertificate subjectName(X501Name subject) {
            this.subject = subject;
            return this;
        }

        public TbsCertificate publicKey(RSAPublicKey publicKey) {
            this.subjectPublicKeyInfo = new SubjectPublicKeyInfo(publicKey);
            return this;
        }

        public RSAPublicKey publicKey() throws GeneralSecurityException {
            return subjectPublicKeyInfo.getPublicKey();
        }

        public TbsCertificate addExtension(Extension.ExtensionType extension) {
            if (extensions == null) extensions = new CertificateExtensions();
            extensions.add(extension);
            return this;
        }

        public CertificateExtensions extensions() {
            return extensions;
        }
    }

    public static class CertificateVersion {
        private Der der;
        protected final Der.INTEGER version;

        public CertificateVersion(Der der) {
            this.der = der;
            this.version = (Der.INTEGER) ((DerContextSpecificValue) der).parse();
        }

        public CertificateVersion(int version) {
            this.version = new Der.INTEGER(version);
        }

        public void dump(PrintStream out, String fieldName, String indent, boolean debug) {
            out.println(indent + fieldName + ": " + version.longValue() + (debug ? " " + der : ""));
        }

        public Der toDer() {
            return new DerContextSpecificValue(0xA0, version.toByteArray());
        }
    }

    public static class Validity {
        protected final Der.UTCTime notBefore;
        protected final Der.UTCTime notAfter;

        public Validity(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            this.notBefore = (Der.UTCTime)iterator.next(); // Inexact - should be DerTimestamp of either UTCTime or GeneralizedTime
            this.notAfter = (Der.UTCTime)iterator.next();
        }

        public Validity(ZonedDateTime notBefore, ZonedDateTime notAfter) {
            this.notBefore = new Der.UTCTime(notBefore);
            this.notAfter = new Der.UTCTime(notAfter);
        }

        public ZonedDateTime getNotBefore() {
            return notBefore.getDateTime();
        }

        public ZonedDateTime getNotAfter() {
            return notAfter.getDateTime();
        }

        public void dump(PrintStream out, String fieldName, String indent) {
            out.println(indent + fieldName + "=" + notBefore.getDateTime() + " to " + notAfter.getDateTime());
        }

        public Der toDer() {
            return new Der.SEQUENCE(List.of(notBefore, notAfter));
        }
    }

    public static class CertificateExtensions {
        private Der der;
        protected List<Extension> extensions = new ArrayList<>();

        public CertificateExtensions(Der der) {
            this.der = der;
            Der value = ((DerContextSpecificValue)der).parse();
            Iterator<Der> iterator = ((Der.SEQUENCE) value).iterator();
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

        public Der toDer() {
            List<Der> elements = extensions.stream().map(Extension::toDer).collect(Collectors.toList());
            return new DerContextSpecificValue(0xA3, new Der.SEQUENCE(elements).toByteArray());
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
    }

    public void dump(PrintStream out, boolean debug) {
        out.println("X509Certificate:" + (debug ? " " + der : ""));
        tbsCertificate.dump(out, "tbsCertificate", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signatureValue" + "=" + signatureValue.describeValue());
    }

}
