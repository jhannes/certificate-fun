package io.liquidpki.pkcs12;

import io.liquidpki.der.Der;
import io.liquidpki.der.DerContextSpecificValue;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ContentInfo {
    private final Der.OBJECT_IDENTIFIER type;
    private final Der.OCTET_STRING safeContents;
    private Der.SEQUENCE der;

    private List<SafeBag> safeBagList = new ArrayList<>();

    public ContentInfo(Der.SEQUENCE der) {
        this.der = der;
        Iterator<Der> iterator = der.iterator();
        type = (Der.OBJECT_IDENTIFIER) iterator.next();
        safeContents = (Der.OCTET_STRING) ((DerContextSpecificValue) iterator.next()).parse();
        Der.SEQUENCE safeBagSequence = (Der.SEQUENCE) Der.parse(safeContents.byteArray());
        Iterator<Der> safeBagIterator = safeBagSequence.iterator();
        while (safeBagIterator.hasNext()) {
            safeBagList.add(new SafeBag((Der.SEQUENCE) safeBagIterator.next()));
        }
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + getClass().getSimpleName() + ": " + der);
        out.println(indent + "  type: " + type);
        for (SafeBag safeBag : safeBagList) {
            safeBag.output(out, indent + "  ");
        }

    }

    public static class SafeBag {
        private final Der.OBJECT_IDENTIFIER bagId;
        private final Der contents;

        public SafeBag(Der.SEQUENCE der) {
            Iterator<Der> iterator = der.iterator();
            bagId = (Der.OBJECT_IDENTIFIER) iterator.next();
            Der bagValue = ((DerContextSpecificValue) iterator.next()).parse();
            if (bagValue instanceof Der.OCTET_STRING) {
                this.contents = PKCS12BagSet.create((Der.SEQUENCE) Der.parse(((Der.OCTET_STRING)bagValue).byteArray()));
            } else {
                this.contents = bagValue;
            }

        }

        public void output(PrintStream out, String indent) {
            out.println(indent + getClass().getSimpleName() + ": " + bagId);
            contents.output(out, indent + "  ");
        }
    }

    private static class PKCS12BagSet {
        public static Der create(Der.SEQUENCE sequence) {
            Iterator<Der> iterator = sequence.iterator();
            Der.OBJECT_IDENTIFIER bagId = (Der.OBJECT_IDENTIFIER) iterator.next();

            return null;
        }
    }
}
