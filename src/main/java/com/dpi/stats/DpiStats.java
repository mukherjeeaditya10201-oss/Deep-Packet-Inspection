package com.dpi.stats;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Aggregate counters for the run, printed as a summary once processing
 * finishes (mirrors the "forwarded vs dropped" report the original
 * engine prints).
 */
public final class DpiStats {

    private final AtomicLong totalPackets = new AtomicLong();
    private final AtomicLong forwardedPackets = new AtomicLong();
    private final AtomicLong droppedPackets = new AtomicLong();

    public void incrementTotal() {
        totalPackets.incrementAndGet();
    }

    public void incrementForwarded() {
        forwardedPackets.incrementAndGet();
    }

    public void incrementDropped() {
        droppedPackets.incrementAndGet();
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }

    public long getForwardedPackets() {
        return forwardedPackets.get();
    }

    public long getDroppedPackets() {
        return droppedPackets.get();
    }
}
