package com.dpi.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * The 24-byte global header that begins every classic .pcap file.
 * Detects byte order from the magic number so files written on either
 * a big-endian or little-endian machine can be read correctly.
 */
public final class PcapGlobalHeader {

    // Canonical magic number values, independent of byte order - the
    // ByteBuffer's configured order is what actually produces the
    // correct on-disk byte sequence for a given endianness.
    private static final int MAGIC_MICROSECONDS = 0xa1b2c3d4;
    private static final int MAGIC_NANOSECONDS = 0xa1b23c4d;

    private final ByteOrder byteOrder;
    private final int versionMajor;
    private final int versionMinor;
    private final int snapLen;
    private final int network;
    private final boolean nanosecondResolution;

    private PcapGlobalHeader(ByteOrder byteOrder, int versionMajor, int versionMinor,
                              int snapLen, int network, boolean nanosecondResolution) {
        this.byteOrder = byteOrder;
        this.versionMajor = versionMajor;
        this.versionMinor = versionMinor;
        this.snapLen = snapLen;
        this.network = network;
        this.nanosecondResolution = nanosecondResolution;
    }

    public static PcapGlobalHeader readFrom(InputStream in) throws IOException {
        byte[] header = readFully(in, 24);

        ByteOrder order;
        boolean nanos;

        int magicAsLittleEndian = ByteBuffer.wrap(header, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int magicAsBigEndian = ByteBuffer.wrap(header, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();

        if (magicAsLittleEndian == MAGIC_MICROSECONDS) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanos = false;
        } else if (magicAsLittleEndian == MAGIC_NANOSECONDS) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanos = true;
        } else if (magicAsBigEndian == MAGIC_MICROSECONDS) {
            order = ByteOrder.BIG_ENDIAN;
            nanos = false;
        } else if (magicAsBigEndian == MAGIC_NANOSECONDS) {
            order = ByteOrder.BIG_ENDIAN;
            nanos = true;
        } else {
            throw new IOException("Not a recognised .pcap file (bad magic number)");
        }

        ByteBuffer buf = ByteBuffer.wrap(header, 4, 20).order(order);
        int major = buf.getShort() & 0xFFFF;
        int minor = buf.getShort() & 0xFFFF;
        buf.getInt(); // thiszone (GMT to local correction), unused
        buf.getInt(); // sigfigs (timestamp accuracy), unused
        int snap = buf.getInt();
        int net = buf.getInt();

        return new PcapGlobalHeader(order, major, minor, snap, net, nanos);
    }

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(24).order(byteOrder);
        buf.putInt(nanosecondResolution ? MAGIC_NANOSECONDS : MAGIC_MICROSECONDS);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(0);
        buf.putInt(0);
        buf.putInt(snapLen);
        buf.putInt(network);
        return buf.array();
    }

    public static PcapGlobalHeader defaultHeader(int network, int snapLen) {
        return new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, 2, 4, snapLen, network, false);
    }

    public ByteOrder getByteOrder() {
        return byteOrder;
    }

    public int getSnapLen() {
        return snapLen;
    }

    public int getNetwork() {
        return network;
    }

    public boolean isNanosecondResolution() {
        return nanosecondResolution;
    }

    static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int total = 0;
        while (total < length) {
            int n = in.read(buf, total, length - total);
            if (n < 0) {
                throw new IOException("Unexpected end of stream while reading pcap header");
            }
            total += n;
        }
        return buf;
    }
}
