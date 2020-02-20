package io.liquidpki.der;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DerCollection implements Der {
    private final int tag;
    private DerValue derValue;
    protected List<Der> children = new ArrayList<>();

    public DerCollection(DerValue derValue) {
        this.tag = derValue.getTag();
        this.derValue = derValue;
        int offset = 1 + derValue.getBytesForLength();
        while (offset < derValue.fullLength()) {
            Der child = Der.parse(derValue.atOffset(offset));
            offset += derValue.atOffset(offset).fullLength();
            this.children.add(child);
        }
    }

    public DerCollection(int tag, List<Der> children) {
        this.tag = tag;
        this.children = children;
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + this);
        for (Der child : children) {
            child.output(out, indent + "  ");
        }
    }

    @Override
    public int fullLength() {
        int payloadLength = children.stream().mapToInt(Der::fullLength).sum();
        int bytesForLength;
        if (payloadLength < 0x80) {
            bytesForLength = 1;
        } else {
            int bitsNeededForNumber = Integer.toBinaryString(payloadLength).length();
            bytesForLength = bitsNeededForNumber/8 + 1;
        }
        return 1 + bytesForLength + payloadLength;
    }

    @Override
    public int getTag() {
        return tag;
    }

    public Der first() {
        return children.get(0);
    }

    public Iterator<Der> iterator() {
        return children.iterator();
    }

    public byte[] toByteArray() {
        return new byte[0];
    }

    @Override
    public String toString() {
        if (derValue != null) {
            return getClass().getSimpleName() + "{" +
                    "tag=" + describeTag() +
                    ", children.size=" + children.size() +
                    ", derValue=" + derValue +
                    '}';
        }
        return getClass().getSimpleName() + "{" +
                "tag=" + describeTag() +
                ", children.size=" + children.size() +
                ", fullLength=" + fullLength() +
                '}';
    }

    protected String describeTag() {
        return "[0x" + Integer.toString(getTag(), 16) + "]";
    }
}
