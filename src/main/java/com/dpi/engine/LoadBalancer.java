package com.dpi.engine;

import com.dpi.connection.Connection;
import com.dpi.connection.ConnectionKey;
import com.dpi.connection.ConnectionTable;
import com.dpi.parser.PacketParser;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.RawPacket;
import com.dpi.stats.DpiStats;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.BlockingQueue;

/**
 * Reads the pcap file from front to back, parses just enough of each
 * packet's headers to compute its connection key, looks up (or creates)
 * that connection, and hands the packet to the worker thread responsible
 * for that connection - always the same worker for a given connection,
 * so per-connection state (SNI, block decision) never needs locking.
 *
 * Non-IP or unparsable frames (ARP, IPv6, etc.) are forwarded immediately
 * without being queued for inspection, matching how a DPI box would pass
 * through traffic it doesn't understand rather than dropping it.
 */
public final class LoadBalancer implements Runnable {

    private final PcapReader reader;
    private final ConnectionTable connectionTable;
    private final List<BlockingQueue<PacketTask>> workerQueues;
    private final OutputWriter outputWriter;
    private final DpiStats stats;
    private volatile IOException failure;

    public LoadBalancer(PcapReader reader, ConnectionTable connectionTable,
                         List<BlockingQueue<PacketTask>> workerQueues,
                         OutputWriter outputWriter, DpiStats stats) {
        this.reader = reader;
        this.connectionTable = connectionTable;
        this.workerQueues = workerQueues;
        this.outputWriter = outputWriter;
        this.stats = stats;
    }

    @Override
    public void run() {
        try {
            long total = 0;
            RawPacket raw;
            while ((raw = reader.nextPacket()) != null) {
                total++;
                dispatch(raw);
            }
            outputWriter.setTotalPackets(total);
            for (BlockingQueue<PacketTask> q : workerQueues) {
                q.put(PacketTask.POISON_PILL);
            }
        } catch (IOException e) {
            failure = e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void dispatch(RawPacket raw) throws InterruptedException {
        ParsedPacket parsed = PacketParser.parse(raw.getData());

        if (!parsed.isValid()) {
            // Not IPv4/TCP/UDP (or malformed) - nothing to inspect, forward
            // it straight through. OutputWriter accounts for it as
            // forwarded once it actually writes the packet out.
            stats.incrementTotal();
            outputWriter.submit(raw.getSequence(), raw, true);
            return;
        }

        ConnectionKey key = ConnectionKey.of(
                parsed.getSrcIp(), parsed.getSrcPort(),
                parsed.getDstIp(), parsed.getDstPort(),
                parsed.getProtocol());
        Connection connection = connectionTable.getOrCreate(key);

        int bucket = key.bucket(workerQueues.size());
        workerQueues.get(bucket).put(new PacketTask(raw, parsed, connection));
    }

    public IOException getFailure() {
        return failure;
    }
}
