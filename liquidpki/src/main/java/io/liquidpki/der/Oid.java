package io.liquidpki.der;

import java.util.Map;
import java.util.logging.Logger;

public class Oid {
    private static Logger logger = Logger.getLogger(Oid.class.getName());

    private static Map<String, String> x509oidMap = Map.of(
            "2.5.4.3", "commonName",
            "2.5.4.10", "organizationName",
            "2.5.4.11", "organizationalUnitName",
            "2.5.4.6", "countryName",
            "2.5.29.19", "basicConstraints",
            "2.5.29.15", "keyUsage",
            "2.5.29.17", "Subject Alternative Name",
            "2.5.29.14", "subjectKeyIdentifier");

    private static Map<String, String> rsaOidMap = Map.of(
            "1.2.840.113549.1.1.11", "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.1", "RSA encryption",
            "1.2.840.113549.1.9.14", "PKCS#9 ExtensionRequest",
            "1.2.840.113549.1.1.13", "sha512WithRSAEncryption"
    );


    public static String get(String objectIdentifier) {
        if (x509oidMap.containsKey(objectIdentifier)) {
            return x509oidMap.get(objectIdentifier);
        } else if (rsaOidMap.containsKey(objectIdentifier)) {
            return rsaOidMap.get(objectIdentifier);
        }
        logger.warning("Unknown oid " + objectIdentifier);
        return null;
    }
}
