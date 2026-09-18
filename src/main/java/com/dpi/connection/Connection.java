package com.dpi.connection;

import java.util.concurrent.atomic.AtomicLong;

/**
 * State kept for one connection across the packets belonging to it.
 * A given connection is always handled by a single worker thread (see
 * ConnectionKey#bucket), so the mutable fields here need no locking -
 * only the counters, which are read for reporting from the main thread
 * at the end of the run, use atomics.
 */
public final class Connection {

    private final ConnectionKey key;
    private volatile String sni;
    private volatile boolean blocked;
    private volatile String blockReason;
    private final AtomicLong packetCount = new AtomicLong();
    private final AtomicLong byteCount = new AtomicLong();

    public Connection(ConnectionKey key) {
        this.key = key;
    }

    public ConnectionKey getKey() {
        return key;
    }

    public String getSni() {
        return sni;
    }

    public void setSni(String sni) {
        if (this.sni == null) {
            this.sni = sni;
        }
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void block(String reason) {
        this.blocked = true;
        this.blockReason = reason;
    }

    public String getBlockReason() {
        return blockReason;
    }

    public void recordPacket(int bytes) {
        packetCount.incrementAndGet();
        byteCount.addAndGet(bytes);
    }

    public long getPacketCount() {
        return packetCount.get();
    }

    public long getByteCount() {
        return byteCount.get();
    }
}
