package io.liquidpki.der;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class DerCollection extends DerValue {
    protected List<Der> children = new ArrayList<>();

    public DerCollection(DerValue derValue) {
        super(derValue);
        int offset = 1 + getBytesForLength();
        while (offset < valueLength()) {
            Der child = Der.parse(bytes, this.offset + offset);
            offset += child.fullLength();
            this.children.add(child);
        }
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + this);
        for (Der child : children) {
            child.output(out, indent + "  ");
        }
    }
}
