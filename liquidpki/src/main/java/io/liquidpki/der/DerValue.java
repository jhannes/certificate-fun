package io.liquidpki.der;

import java.io.PrintStream;

public class DerValue implements Der {
    protected final byte[] bytes;
    protected final int offset;

    public DerValue(byte[] bytes, int offset) {
        this.bytes = bytes;
        this.offset = offset;
    }

    public DerValue(DerValue derValue) {
        this.bytes = derValue.bytes;
        this.offset = derValue.offset;
    }

    public DerValue(int tag, byte[] bytes) {
        this.offset = 0;
        int bytesOfLength = 1;
        this.bytes = new byte[1 + bytesOfLength + bytes.length];
        this.bytes[0] = (byte)(0xff & tag);
        this.bytes[1] = (byte)(0xff & bytes.length);
        System.arraycopy(bytes, 0, this.bytes, 1 + bytesOfLength, bytes.length);
    }

    public byte[] getEncoded() {
        if (offset == 0 && fullLength() == bytes.length) return bytes;
        byte[] encoded = new byte[fullLength()];
        System.arraycopy(bytes, 0, encoded, 0, encoded.length);
        return encoded;
    }

    /** Returns the binary value at pos within the whole buffer of the io.liquidpki.der.DerValue as unsigned [0-255] */
    protected int unsignedVal(int pos) {
        if (pos < 0) {
            throw new ArrayIndexOutOfBoundsException(pos + " in < 0");
        }
        return (0xff & bytes[offset + pos]);
    }

    protected int getBytesForLength() {
        return unsignedVal(1) >= 0b10000000 ? unsignedVal(1) + 1 & ~0b10000000 : 1;
    }

    protected int valueOffset() {
        return offset + 1 + getBytesForLength();
    }

    public int getTag() {
        return unsignedVal(0);
    }

    public int fullLength() {
        return 1 + getBytesForLength() + valueLength();
    }

    public int valueLength() {
        int bytesForLength = getBytesForLength();
        if (bytesForLength > 1) {
            int length = 0;
            for (int i = 1; i < bytesForLength; i++) {
                length <<= 8;
                length |= unsignedVal(1+i);
            }
            return length;
        } else {
            return unsignedVal(1);
        }
    }

    protected long bytesToLong(int offset, int length) {
        long result = 0;
        for (int i = 0; i < length; i++) {
            result <<= Long.BYTES;
            result |= (bytes[offset + i] & 0xFF);
        }
        return result;
    }

    public String toHexBytes() {
        char[] hexChars = new char[fullLength()*2];
        toHex(offset, fullLength(), hexChars, 0);
        return new String(hexChars);
    }

    protected byte[] byteArray() {
        byte[] result = new byte[valueLength()];
        System.arraycopy(bytes, valueOffset(), result, 0, result.length);
        return result;
    }

    /**
     * Prints the binary VALUE of this io.liquidpki.der.DerValue as hex, abbreviated to max 20 characters. If {@link #valueLength()}() is > 20,
     * this method prints the first 10 and the last 5 bytes
     */
    public String describeValue() {
        if (valueLength() < 20) {
            char[] hexChars = new char[valueLength() * 2];
            toHex(valueOffset(), valueLength(), hexChars, 0);
            return new String(hexChars);
        } else {
            char[] hexChars = new char[10 * 2 + 4 + 5 * 2];
            toHex(valueOffset(), 10, hexChars, 0);
            hexChars[20] = hexChars[21] = hexChars[22] = hexChars[23] = '.';
            toHex(valueOffset() + valueLength() -5, 5, hexChars, 24);
            return new String(hexChars);
        }
    }

    protected void toHex(int offset, int length, char[] hexChars, int outputOffset) {
        for (int i = 0; i < length; i++) {
            int v = bytes[offset + i] & 0xFF;
            hexChars[outputOffset + i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[outputOffset + i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
    }

    public void output(PrintStream out, String indent) {
        out.println(indent + this);
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

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

    public DerValue atOffset(int offset) {
        return new DerValue(bytes, this.offset + offset);
    }
}
