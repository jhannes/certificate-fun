This library is probably the stupidest idea I've ever had: I've decided to reimplement from scratch the code needed to generate and read SSL Certificates (X.509 certificates, RFC 5280) and Certification Requests (AKA CSRs, PKCS #10, RFC 2986).

This is a pretty stupid idea as there exists two stable widely and freely available libraries that does the same: the `sun.security.x509` package and the [Bouncy Castle Java cryptography APIs](https://www.bouncycastle.org/java.html).

So why did I do it? Because I was totally unable to understand the code of the aforementioned packages and it was causing my problems when trying to understand, in particular, how to generate Certification Requests (CSRs) in Java. This implementation aims to express the code in a way that communicates the RFC and PKCS specifications underlying the technology. I don't know if it will succeed in creating a more available understanding of the specifications, but it has certainly helped my understanding.

What do I mean by "reimplement from scratch Public Key Cryptography Standards (PKCS) in a way that expresses the standards"?
* The code includes a `io.liquidpki.der` package which implements the ASN.1 DER encoding that's used for X.509 and PKCS #10 files (as well as PKCS #12 - keystores and PKCS #7 - Certification Revocation Lists). `io.liquidpki.der.DerValue` and related classes implement the bit [fiddling specified in the ASN.1/DER encoding](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding)
* The code includes `X509Certificate` and `CertificationRequest` classes which support build, reading, signing and verifying certificates and certification requests, respectively. The constructors and `.toDER` methods of these classes is modelled after the syntax diagrams in the relevant RFCs
* The code does _not_ include implementation of encryption or signing algorithms. The implementations of `java.security.Signature` in particulate and `KeyPairGenerator.getInstance` are sufficient for our needs

The code doesn't work in very many instances:
* [ ] When signing, only SHA256 and SHA512 are looked up correctly
* [ ] Unknown problems mean that it cannot validate the signature of third party libraries 


## Implementation - learning about certificates

### From X.509 Certificates to DER objects

In order to understand the structure of X.509 certificates, feel free to peruse the `io.liquidpki.x509.X509Certificate` class. As per the [RFC 5280](https://tools.ietf.org/html/rfc5280), `X509Certificate#toDER" looks like this:

```java
public Der toDer() {
    return new Der.SEQUENCE(List.of(tbsCertificate.toDer(), signatureAlgorithm.toDer(), signatureValue));
}
```

The member tbsCertificate has the following `.toDER`-method:

```java
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
```

And e.g. `validity.toDER` looks like this:

```java
public Der toDer() {
    return new Der.SEQUENCE(List.of(new Der.UTCTime(notBefore), new Der.UTCTime(notAfter)));
}
```

So, calling `toDER` on a certificate (without extensions) will create a DER object tree like the following:

```java
new Der.SEQUENCE(List.of(
    new Der.SEQUENCE(List.of(
        ..., // version
        new Der.INTEGER(123), // serial number
        ..., // signature
        ..., // issuer
        new Der.SEQUENCE(List.of(new Der.UTCTime(notBefore), new Der.UTCTime(notAfter))), // validity
        ..., // subject
        ...)
    ))
    new Der.SEQUENCE(List.of(new Der.OBJECT_IDENTIFIER(algorithmOid), new Der.NULL())), // algorithm identifiser
    new Der.BIT_STRING()
))
```

### From DER to bytes

When we have retrieved an object tree of DER objects from the certificate, these can be serialized with `toByteArray` or `write`. For example, our validity of `new Der.SEQUENCE(List.of(new Der.UTCTime(notBefore), new Der.UTCTime(notAfter)))` will in `Der.SEQUENCE.write`produce:

```java
class Der.SEQUENCE {
    @Override
    public void write(OutputStream output) throws IOException {
        output.write(getTag());
        Der.writeLength(output, valueLength);
        for (Der child : children) {
            child.write(output);
        }
    }
}

class UTCTime extends DerValue {
    public UTCTime(DerValue derValue) {
        super(derValue);
    }

    public UTCTime(ZonedDateTime dateTime) {
        super(0x17, dateTime.format(DateTimeFormatter.ofPattern("yyMMddHHmmssX")).getBytes());
    }
}

public class DerValue implements Der {
    private final byte[] bytes;
    private final int offset;

    public DerValue(int tag, byte[] bytes) {
        this.offset = 0;
        buffer.write(0xff & tag);
        Der.writeLength(buffer, bytes.length);
        buffer.write(bytes);
        this.bytes = buffer.toByteArray();
    }

    @Override
    public void write(OutputStream output) throws IOException {
        output.write(bytes, offset, fullLength());
    }
}
```


