package io.liquidpki.der;

import java.util.Map;
import java.util.logging.Logger;

public class Oid {
    private static Logger logger = Logger.getLogger(Oid.class.getName());

    private static Map<String, String> oidMap = Map.of(
            "2.5.4.3", "commonName",
            "2.5.4.10", "organizationName",
            "2.5.4.11", "organizationalUnitName",
            "2.5.4.6", "countryName",
            "2.5.29.19", "basicConstraints",
            "2.5.29.15", "keyUsage",
            "2.5.29.14", "subjectKeyIdentifier",
            "1.2.840.113549.1.1.13", "sha512WithRSAEncryption"
    );


    public static String get(String objectIdentifier) {
        if (!oidMap.containsKey(objectIdentifier)) {
            logger.warning("Unknown oid " + objectIdentifier);
        }
        return oidMap.get(objectIdentifier);
    }
}
