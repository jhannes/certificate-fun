package io.liquidpki.der;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

// TODO: Load this from a resource file
public class Oid {
    private static Logger logger = Logger.getLogger(Oid.class.getName());

    private static Map<String, String> microsoftAttributes = Map.of(
            "1.3.6.1.4.1.311.60.2.1.2", "State or province",
            "1.3.6.1.4.1.311.60.2.1.3", "Country",
            "1.3.14.3.2.26", "Secure Hash Algorithm, revision 1 (SHA-1)"
    );

    private static Map<String, String> x500Attributes = Map.of(
            "2.5.4.3", "commonName",
            "2.5.4.5", "serialNumber",
            "2.5.4.6", "countryName",
            "2.5.4.7", "localityName",
            "2.5.4.8", "stateOrProvinceName",
            "2.5.4.10", "organizationName",
            "2.5.4.15", "businessCategory",
            "2.5.4.11", "organizationalUnitName"
    );

    private static Map<String, String> x509oidMap = Map.of(
            "2.5.29.19", "basicConstraints",
            "2.5.29.15", "keyUsage",
            "2.5.29.17", "Subject Alternative Name",
            "2.5.29.14", "subjectKeyIdentifier",
            "2.5.29.31", "CRL Distribution Points",
            "2.5.29.32", "Certificate Policies",
            "2.5.29.37", "Extended Key Usage",
            "2.5.29.35", "certificateExtension"
    );
    private static Map<String, String> rsaAlgOidMap = new HashMap<>(Map.of(
            "1.2.840.113549.1.1.1", "RSA encryption",
            "1.2.840.113549.1.1.5", "sha1-with-rsa-signature",
            "1.2.840.113549.1.1.11", "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.13", "sha512WithRSAEncryption"
    ));

    private static Map<String, String> rsaOidMap = new HashMap<>(Map.of(
            "1.2.840.113549.1.9.14", "PKCS#9 ExtensionRequest",
            "1.2.840.113549.1.7.1", "id-data",
            "1.2.840.113549.1.7.2", "signedData",
            "1.2.840.113549.1.7.3", "envelopedData",
            "1.2.840.113549.1.7.4", "signedAndEnvelopedData",
            "1.2.840.113549.1.7.5", "digestedData",
            "1.2.840.113549.1.7.6", "encryptedData"));
    public static final String PKCS8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2";

    static {
        rsaOidMap.put(PKCS8ShroudedKeyBag, "pkcs8ShroudedKeyBag");
        rsaOidMap.put("1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC");
        rsaOidMap.put("1.2.840.113549.1.12.1.6", "pbewithSHAAnd40BitRC2-CBC");
        rsaOidMap.put("1.2.840.113549.1.9.20", "friendlyName");
        rsaOidMap.put("1.2.840.113549.1.9.21", "localKeyId");
    }


    public static String get(String objectIdentifier) {
        if (microsoftAttributes.containsKey(objectIdentifier)) {
            return microsoftAttributes.get(objectIdentifier);
        } else if (x500Attributes.containsKey(objectIdentifier)) {
            return x500Attributes.get(objectIdentifier);
        } else if (x509oidMap.containsKey(objectIdentifier)) {
            return x509oidMap.get(objectIdentifier);
        } else if (rsaAlgOidMap.containsKey(objectIdentifier)) {
            return rsaAlgOidMap.get(objectIdentifier);
        } else if (rsaOidMap.containsKey(objectIdentifier)) {
            return rsaOidMap.get(objectIdentifier);
        }
        logger.warning("Unknown oid " + objectIdentifier);
        return null;
    }

    public static String getPublicKeyAlgorithm(String algorithm) {
        if (algorithm.equals("RSA")) {
            return "1.2.840.113549.1.1.13";
        }
        throw new IllegalArgumentException("Unknown algorithm " + algorithm);
    }

    public static String getSignatureAlgorithm(String algorithm) {
        if (algorithm.equals("RSA")) {
            return "1.2.840.113549.1.1.1";
        }
        throw new IllegalArgumentException("Unknown algorithm " + algorithm);
    }
}
