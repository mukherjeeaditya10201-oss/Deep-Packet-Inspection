package com.dpi.engine;

import com.dpi.pcap.PcapWriter;
import com.dpi.pcap.RawPacket;
import com.dpi.stats.DpiStats;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Because packets are fanned out across several fast-path worker threads
 * (grouped by connection so state stays consistent), results can finish
 * out of the original capture order. This class puts them back in order
 * before writing forwarded packets to the output .pcap - a single writer
 * avoids interleaving/corrupting the output file and keeps timestamps
 * monotonic for tools like Wireshark that read the result afterwards.
 *
 * Workers call {@link #submit} as each packet's verdict is ready; a
 * dedicated writer thread drains packets strictly in sequence order.
 */
public final class OutputWriter implements Runnable {

    private final PcapWriter writer;
    private final DpiStats stats;

    private final Object lock = new Object();
    private final Map<Long, Result> pending = new HashMap<>();
    private long nextSequence = 0;
    private long written = 0;
    // -1 means "the load balancer hasn't finished reading the capture yet,
    // so the total packet count isn't known" - set once via setTotalPackets.
    private long totalPackets = -1;
    private volatile IOException failure;

    public OutputWriter(PcapWriter writer, DpiStats stats) {
        this.writer = writer;
        this.stats = stats;
    }

    /** Called by worker threads once a packet's forward/drop decision is known. */
    public void submit(long sequence, RawPacket raw, boolean forward) {
        synchronized (lock) {
            pending.put(sequence, new Result(raw, forward));
            lock.notifyAll();
        }
    }

    /** Called by the load balancer once it has read the whole capture file. */
    public void setTotalPackets(long total) {
        synchronized (lock) {
            this.totalPackets = total;
            lock.notifyAll();
        }
    }

    @Override
    public void run() {
        try {
            while (true) {
                Result result;
                synchronized (lock) {
                    while (!pending.containsKey(nextSequence)) {
                        if (totalPackets >= 0 && written >= totalPackets) {
                            return;
                        }
                        lock.wait();
                    }
                    result = pending.remove(nextSequence);
                    nextSequence++;
                }
                if (result.forward) {
                    writer.writePacket(result.raw);
                    stats.incrementForwarded();
                } else {
                    stats.incrementDropped();
                }
                written++;
                synchronized (lock) {
                    if (totalPackets >= 0 && written >= totalPackets) {
                        return;
                    }
                }
            }
        } catch (IOException e) {
            failure = e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public IOException getFailure() {
        return failure;
    }

    private static final class Result {
        final RawPacket raw;
        final boolean forward;

        Result(RawPacket raw, boolean forward) {
            this.raw = raw;
            this.forward = forward;
        }
    }
}
