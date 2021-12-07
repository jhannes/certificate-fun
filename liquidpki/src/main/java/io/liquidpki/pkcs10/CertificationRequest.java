package io.liquidpki.pkcs10;

import io.liquidpki.common.AlgorithmIdentifier;
import io.liquidpki.common.CertificateExtensions;
import io.liquidpki.common.Extension;
import io.liquidpki.der.Der;
import io.liquidpki.der.DerCollection;
import io.liquidpki.der.DerValue;

import java.io.PrintStream;
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

    public CertificationRequest(CertificationRequestInfo info, AlgorithmIdentifier algorithm, byte[] signature) {
        this.certificationRequestInfo = info;
        this.signatureAlgorithm = algorithm;
        this.signature = new Der.BIT_STRING(signature);
    }

    public CertificationRequest info(CertificationRequestInfo certificationRequestInfo) {
        this.certificationRequestInfo = certificationRequestInfo;
        return this;
    }

    public CertificationRequestInfo info() {
        return certificationRequestInfo;
    }

    public Der toDer() {
        return new Der.SEQUENCE(List.of(certificationRequestInfo.toDer(), signatureAlgorithm.toDer(), signature));
    }

    public void dump(PrintStream out, boolean debug) {
        out.println("CertificationRequest:" + (debug ? " " + der : ""));
        certificationRequestInfo.dump(out, "certificationRequestInfo", "  ", debug);
        signatureAlgorithm.dump(out, "signatureAlgorithm", "  ", debug);
        out.println("  " + "signature" + "=" + signature.describeValue() + " [length=" + signature.valueLength() + "]");
    }

}
