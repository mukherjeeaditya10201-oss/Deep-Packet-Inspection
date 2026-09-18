package com.dpi.pcap;

/**
 * A single packet record as read from a .pcap file: capture timestamp
 * plus the raw bytes of the frame (usually starting with an Ethernet header).
 */
public final class RawPacket {

    private final long sequence;
    private final long timestampSeconds;
    private final long timestampMicros;
    private final byte[] data;
    private final int originalLength;

    public RawPacket(long sequence, long timestampSeconds, long timestampMicros,
                      byte[] data, int originalLength) {
        this.sequence = sequence;
        this.timestampSeconds = timestampSeconds;
        this.timestampMicros = timestampMicros;
        this.data = data;
        this.originalLength = originalLength;
    }

    public long getSequence() {
        return sequence;
    }

    public long getTimestampSeconds() {
        return timestampSeconds;
    }

    public long getTimestampMicros() {
        return timestampMicros;
    }

    public byte[] getData() {
        return data;
    }

    public int getOriginalLength() {
        return originalLength;
    }
}
