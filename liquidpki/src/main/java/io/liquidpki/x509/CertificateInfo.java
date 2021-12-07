package io.liquidpki.x509;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.CertificateExtensions;
import io.liquidpki.common.Extension;
import io.liquidpki.common.SubjectPublicKeyInfo;
import io.liquidpki.common.X500Name;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerContextSpecificValue;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class CertificateInfo {
    protected CertificateVersion version;
    protected Der.INTEGER serialNumber;
    protected AlgorithmIdentifier signature; // nullable
    protected X500Name issuer;
    protected Validity validity;
    protected X500Name subject;
    protected SubjectPublicKeyInfo subjectPublicKeyInfo; // nullable
    protected CertificateExtensions extensions;
    private Der der;

    public CertificateInfo(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        version = new CertificateVersion(iterator.next());
        serialNumber = (Der.INTEGER) iterator.next();
        signature = new AlgorithmIdentifier(iterator.next());
        issuer = new X500Name(iterator.next());
        validity = new Validity(iterator.next());
        subject = new X500Name(iterator.next());
        subjectPublicKeyInfo = new SubjectPublicKeyInfo(iterator.next());
        extensions = new CertificateExtensions((Der.SEQUENCE) ((DerContextSpecificValue) iterator.next()).parse());
    }

    public CertificateInfo() {
        version = new CertificateVersion(3);
        serialNumber = new Der.INTEGER(1);
        signature = null;
        issuer = new X500Name();
        validity = new Validity(ZonedDateTime.now(), ZonedDateTime.now().plusMonths(6));
        subject = new X500Name();
        subjectPublicKeyInfo = null;
        extensions = null;
    }

    public Der toDer() {
        List<Der> children = new ArrayList<>(List.of(
                version.toDer(),
                serialNumber,
                signature.toDer(),
                issuer.toDer(),
                validity.toDer(),
                subject.toDer(),
                subjectPublicKeyInfo.toDer())
        );
        if (extensions != null) {
            children.add(new DerContextSpecificValue(0xA3, extensions.toDer().toByteArray()));
        }
        return new Der.SEQUENCE(children);
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

    public CertificateInfo version(int version) {
        this.version = new CertificateVersion(version);
        return this;
    }

    public int version() {
        return (int) this.version.version.longValue();
    }

    public CertificateInfo serialNumber(long serialNumber) {
        this.serialNumber = new Der.INTEGER(serialNumber);
        return this;
    }

    public CertificateInfo signature(String signatureAlgorithm) {
        this.signature = new AlgorithmIdentifier(signatureAlgorithm);
        return this;
    }

    public CertificateInfo issuerName(X500Name issuer) {
        this.issuer = issuer;
        return this;
    }

    public CertificateInfo validity(ZonedDateTime notBefore, ZonedDateTime notAfter) {
        this.validity = new Validity(notBefore, notAfter);
        return this;
    }

    public CertificateInfo subjectName(X500Name subject) {
        this.subject = subject;
        return this;
    }

    public CertificateInfo publicKey(PublicKey publicKey) {
        this.subjectPublicKeyInfo = new SubjectPublicKeyInfo((RSAPublicKey) publicKey);
        return this;
    }

    public RSAPublicKey publicKey() throws GeneralSecurityException {
        return subjectPublicKeyInfo.getPublicKey();
    }

    public CertificateInfo addExtension(Extension.ExtensionType extension) {
        if (extensions == null) extensions = new CertificateExtensions();
        extensions.add(extension);
        return this;
    }

    public CertificateInfo extensions(CertificateExtensions extensions) {
        this.extensions = extensions;
        return this;
    }

    public CertificateExtensions extensions() {
        return extensions;
    }

    public SignedCertificate signWithKey(PrivateKey privateKey, String signatureAlgorithm) throws GeneralSecurityException {
        this.signature(Oid.getSignatureAlgorithm(privateKey.getAlgorithm()));
        byte[] bytes = toDer().toByteArray();
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(bytes, 0, bytes.length);
        byte[] sign = signature.sign();
        return new SignedCertificate(this, this.signature, sign);
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
        protected final ZonedDateTime notBefore;
        protected final ZonedDateTime notAfter;

        public Validity(Der der) {
            Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
            this.notBefore = ((Der.UTCTime)iterator.next()).getDateTime(); // Inexact - should be DerTimestamp of either UTCTime or GeneralizedTime
            this.notAfter = ((Der.UTCTime)iterator.next()).getDateTime();
        }

        public Validity(ZonedDateTime notBefore, ZonedDateTime notAfter) {
            this.notBefore = notBefore;
            this.notAfter = notAfter;
        }

        public ZonedDateTime getNotBefore() {
            return notBefore;
        }

        public ZonedDateTime getNotAfter() {
            return notAfter;
        }

        public void dump(PrintStream out, String fieldName, String indent) {
            out.println(indent + fieldName + "=" + notBefore + " to " + notAfter);
        }

        public Der toDer() {
            return new Der.SEQUENCE(List.of(new Der.UTCTime(notBefore), new Der.UTCTime(notAfter)));
        }
    }
}
