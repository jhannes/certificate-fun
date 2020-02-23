package io.liquidpki.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DerCollection implements Der {
    private final int tag;
    protected List<Der> children = new ArrayList<>();
    private int valueLength;

    public DerCollection(DerValue derValue) {
        this.tag = derValue.getTag();
        this.valueLength = derValue.valueLength();
        int offset = 0;
        while (offset < derValue.valueLength()) {
            Der child = Der.parse(derValue.atOffset(offset));
            this.children.add(child);
            offset += child.fullLength();
        }
    }

    public DerCollection(int tag, List<? extends Der> children) {
        this.tag = tag;
        this.valueLength = children.stream().mapToInt(Der::fullLength).sum();
        this.children = new ArrayList<>(children);
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
        return valueLength < 0x80 ? 1 : 1 + Der.bytesInNumber(valueLength);
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

    @Override
    public String toString() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        writeStart(buffer);
        return getClass().getSimpleName() + "{" +
                "tag=" + describeTag() +
                ", length=" + (1+getBytesForLength()) + "+" + valueLength +
                ", start=[0x" + Der.toHex(buffer.toByteArray()) + "...]" +
                ", children.size=" + children.size() +
                '}';
    }

    protected String describeTag() {
        return "[0x" + Integer.toString(getTag(), 16) + "]";
    }

    @Override
    public void write(OutputStream output) throws IOException {
        writeStart(output);
        for (Der child : children) {
            child.write(output);
        }
    }

    public void writeStart(OutputStream output) {
        try {
            output.write(getTag());
            Der.writeLength(output, valueLength);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
