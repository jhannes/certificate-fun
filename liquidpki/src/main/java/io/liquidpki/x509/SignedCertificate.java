package io.liquidpki.x509;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerContextSpecificValue;
import io.liquidpki.der.Oid;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.ZonedDateTime;
import java.util.Iterator;
import java.util.List;

/**
 * As defined by https://tools.ietf.org/html/rfc5280
 */
public class SignedCertificate {

    private Der der;
    protected CertificateInfo tbsCertificate;
    protected AlgorithmIdentifier signatureAlgorithm;
    protected Der.BIT_STRING signatureValue;

    public SignedCertificate(byte[] derBytes) {
        this(Der.parse(derBytes));
    }

    public SignedCertificate(Der der) {
        this.der = der;
        Iterator<Der> iterator = ((Der.SEQUENCE) der).iterator();
        this.tbsCertificate = new CertificateInfo(iterator.next());
        this.signatureAlgorithm = new AlgorithmIdentifier(iterator.next());
        this.signatureValue = (Der.BIT_STRING)iterator.next();
    }

    public SignedCertificate(CertificateInfo certificateInfo, AlgorithmIdentifier signatureAlgorithm, byte[] signature) {
        this.tbsCertificate = certificateInfo;
        this.signatureAlgorithm = signatureAlgorithm;
        signatureValue = new Der.BIT_STRING(signature);
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(tbsCertificate.toDer(), signatureAlgorithm.toDer(), signatureValue));
    }

    public void dump(PrintStream out, boolean debug) {
        out.println("X509Certificate:" + (debug ? " " + der : ""));
        tbsCertificate.dump(out, "tbsCertificate", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signatureValue" + "=" + signatureValue.describeValue());
    }
}
