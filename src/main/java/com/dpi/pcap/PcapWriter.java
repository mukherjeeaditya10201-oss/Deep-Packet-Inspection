package com.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a new .pcap file, always in little-endian /
 * microsecond-resolution form (the most widely compatible variant).
 */
public final class PcapWriter implements Closeable {

    private final BufferedOutputStream out;

    public PcapWriter(String path, int network, int snapLen) throws IOException {
        this.out = new BufferedOutputStream(new FileOutputStream(path), 1 << 16);
        out.write(PcapGlobalHeader.defaultHeader(network, snapLen).toBytes());
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt((int) packet.getTimestampSeconds());
        header.putInt((int) packet.getTimestampMicros());
        header.putInt(packet.getData().length);
        header.putInt(packet.getOriginalLength());
        out.write(header.array());
        out.write(packet.getData());
    }

    @Override
    public synchronized void close() throws IOException {
        out.flush();
        out.close();
    }
}
