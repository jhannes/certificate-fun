package io.liquidpki.der;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DerCollection implements Der {
    private final int tag;
    private DerValue derValue;
    protected List<Der> children = new ArrayList<>();
    private int valueLength;

    public DerCollection(DerValue derValue) {
        this.tag = derValue.getTag();
        this.valueLength = derValue.valueLength();
        this.derValue = derValue;
        int offset = 1 + derValue.getBytesForLength();
        while (offset < derValue.fullLength()) {
            this.children.add(Der.parse(derValue.atOffset(offset)));
            offset += derValue.atOffset(offset).fullLength();
        }
    }

    public DerCollection(int tag, List<Der> children) {
        this.tag = tag;
        this.valueLength = children.stream().mapToInt(Der::fullLength).sum();
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
        return 1 + getBytesForLength() + valueLength;
    }

    public int getBytesForLength() {
        int bytesForLength;
        if (valueLength < 0x80) {
            bytesForLength = 1;
        } else {
            int bitsNeededForNumber = Integer.toBinaryString(valueLength).length();
            bytesForLength = bitsNeededForNumber/8 + 1;
        }
        return bytesForLength;
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
                    ", length=" + (1+getBytesForLength()) + "+" + valueLength +
                    ", children.size=" + children.size() +
                    ", derValue=" + derValue +
                    '}';
        }
        return getClass().getSimpleName() + "{" +
                "tag=" + describeTag() +
                ", length=" + (1+getBytesForLength()) + "+" + valueLength +
                ", children.size=" + children.size() +
                '}';
    }

    protected String describeTag() {
        return "[0x" + Integer.toString(getTag(), 16) + "]";
    }

    @Override
    public void write(OutputStream output) throws IOException {
        output.write(getTag());
        Der.writeLength(output, valueLength);
        for (Der child : children) {
            child.write(output);
        }
    }
}
