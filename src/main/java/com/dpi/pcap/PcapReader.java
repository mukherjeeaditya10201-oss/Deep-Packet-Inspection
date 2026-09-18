package com.dpi.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets sequentially out of a classic .pcap capture file.
 * This is a small, dependency-free reader (no libpcap binding needed) -
 * it understands just enough of the file format to hand back each
 * packet's timestamp and raw bytes in order.
 */
public final class PcapReader implements Closeable {

    private static final int RECORD_HEADER_LEN = 16;

    private final InputStream in;
    private final PcapGlobalHeader globalHeader;
    private long sequence = 0;

    public PcapReader(String path) throws IOException {
        this.in = new BufferedInputStream(new FileInputStream(path), 1 << 16);
        this.globalHeader = PcapGlobalHeader.readFrom(in);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    /**
     * Reads the next packet from the file, or returns null at end of file.
     */
    public RawPacket nextPacket() throws IOException {
        byte[] recordHeaderBytes;
        try {
            recordHeaderBytes = PcapGlobalHeader.readFully(in, RECORD_HEADER_LEN);
        } catch (IOException eof) {
            return null;
        }

        ByteBuffer rec = ByteBuffer.wrap(recordHeaderBytes).order(globalHeader.getByteOrder());
        long tsSec = rec.getInt() & 0xFFFFFFFFL;
        long tsSubSec = rec.getInt() & 0xFFFFFFFFL;
        long inclLen = rec.getInt() & 0xFFFFFFFFL;
        long origLen = rec.getInt() & 0xFFFFFFFFL;

        if (inclLen > globalHeader.getSnapLen() + 65536) {
            // Sanity guard against a corrupt/truncated capture rather than
            // trying to allocate an absurd buffer.
            throw new IOException("Implausible captured length in pcap record: " + inclLen);
        }

        byte[] data = PcapGlobalHeader.readFully(in, (int) inclLen);
        long micros = globalHeader.isNanosecondResolution() ? tsSubSec / 1000L : tsSubSec;

        return new RawPacket(sequence++, tsSec, micros, data, (int) origLen);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
