package io.liquidpki.der;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;

public class DerValue implements Der {
    private final byte[] bytes;
    private final int offset;

    public DerValue(byte[] bytes, int offset) {
        if (offset < 0) {
            throw new IllegalArgumentException("offset=" + offset);
        }
        this.bytes = bytes;
        this.offset = offset;
    }

    public DerValue(DerValue derValue) {
        this.bytes = derValue.bytes;
        this.offset = derValue.offset;
    }

    public DerValue(int tag, byte[] bytes) {
        this.offset = 0;
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            buffer.write(0xff & tag);
            Der.writeLength(buffer, bytes.length);
            buffer.write(bytes);
            this.bytes = buffer.toByteArray();
        } catch (IOException cannotHappen) {
            throw new RuntimeException(cannotHappen);
        }
    }

    public int getTag() {
        return unsignedValHeader(0);
    }

    public int valueLength() {
        int bytesForLength = getBytesForLength();
        if (bytesForLength > 1) {
            int length = 0;
            for (int i = 1; i < bytesForLength; i++) {
                length <<= 8;
                length |= unsignedValHeader(1+i);
            }
            return length;
        } else {
            return unsignedValHeader(1);
        }
    }

    public int fullLength() {
        return 1 + getBytesForLength() + valueLength();
    }

    public DerValue atOffset(int offset) {
        return new DerValue(bytes, valueOffset() + offset);
    }

    /** Returns the binary value at pos within the value of the io.liquidpki.der.DerValue as unsigned [0-255] */
    protected int unsignedVal(int pos) {
        if (pos < 0 || valueLength() <= pos) {
            throw new ArrayIndexOutOfBoundsException(pos + " not in [0, " + valueLength() + ">");
        }
        return (0xff & bytes[valueOffset() + pos]);
    }

    /** Returns the binary value at pos within the whole buffer of the io.liquidpki.der.DerValue as unsigned [0-255] */
    private int unsignedValHeader(int pos) { // Should be private as implementations should stay away from length calculation!
        if (pos < 0) {
            throw new ArrayIndexOutOfBoundsException(pos + " in < 0");
        }
        return (0xff & bytes[offset + pos]);
    }

    private int getBytesForLength() {
        return unsignedValHeader(1) >= 0b10000000 ? unsignedValHeader(1) + 1 & ~0b10000000 : 1;
    }

    private int valueOffset() {
        return offset + 1 + getBytesForLength();
    }

    protected long bytesToLong() {
        long result = 0;
        for (int i = 0; i < valueLength(); i++) {
            result <<= Long.BYTES;
            result |= unsignedVal(i);
        }
        return result;
    }

    protected byte[] byteArray() {
        byte[] result = new byte[valueLength()];
        System.arraycopy(bytes, valueOffset(), result, 0, result.length);
        return result;
    }

    protected String stringValue(Charset charset) {
        return new String(bytes, valueOffset(), valueLength(), charset);
    }

    /**
     * Prints the binary VALUE of this io.liquidpki.der.DerValue as hex, abbreviated to max 20 characters. If {@link #valueLength()}() is > 20,
     * this method prints the first 10 and the last 5 bytes
     */
    public String describeValue() {
        if (valueLength() < 20) {
            char[] hexChars = new char[valueLength() * 2];
            toHex(0, valueLength(), hexChars, 0);
            return new String(hexChars);
        } else {
            char[] hexChars = new char[10 * 2 + 4 + 5 * 2];
            toHex(0, 10, hexChars, 0);
            hexChars[20] = hexChars[21] = hexChars[22] = hexChars[23] = '.';
            toHex(valueLength() -5, 5, hexChars, 24);
            return new String(hexChars);
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    protected void toHex(int offset, int length, char[] hexChars, int outputOffset) {
        for (int i = 0; i < length; i++) {
            int v = unsignedVal(offset + i);
            hexChars[outputOffset + i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[outputOffset + i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + this);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "tag=" + describeTag() +
                ", offset=" + offset +
                ", length=" + (1+getBytesForLength()) + "+" + valueLength() +
                ", value=" + printValue() +
                '}';
    }

    protected String printValue() {
        return describeValue();
    }

    protected String describeTag() {
        return "[0x" + Integer.toString(getTag(), 16) + "]";
    }

    @Override
    public void write(OutputStream output) throws IOException {
        output.write(bytes, offset, fullLength());
    }
}
