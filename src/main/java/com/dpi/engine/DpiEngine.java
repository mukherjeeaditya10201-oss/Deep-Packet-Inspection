package com.dpi.engine;

import com.dpi.connection.ConnectionTable;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.rules.RuleEngine;
import com.dpi.stats.DpiStats;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Top-level orchestrator: one load-balancer thread reading the capture,
 * a pool of fast-path worker threads doing the actual inspection, and one
 * writer thread producing the output .pcap in the original packet order.
 */
public final class DpiEngine {

    private final String inputPath;
    private final String outputPath;
    private final RuleEngine ruleEngine;
    private final int workerCount;

    private final ConnectionTable connectionTable = new ConnectionTable();
    private final DpiStats stats = new DpiStats();

    public DpiEngine(String inputPath, String outputPath, RuleEngine ruleEngine, int workerCount) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.ruleEngine = ruleEngine;
        this.workerCount = workerCount;
    }

    public DpiStats run() throws IOException, InterruptedException {
        try (PcapReader reader = new PcapReader(inputPath)) {
            try (PcapWriter writer = new PcapWriter(outputPath,
                    reader.getGlobalHeader().getNetwork(), reader.getGlobalHeader().getSnapLen())) {

                OutputWriter outputWriter = new OutputWriter(writer, stats);
                Thread writerThread = new Thread(outputWriter, "dpi-writer");
                writerThread.start();

                List<BlockingQueue<PacketTask>> queues = new ArrayList<>(workerCount);
                List<Thread> workerThreads = new ArrayList<>(workerCount);
                for (int i = 0; i < workerCount; i++) {
                    BlockingQueue<PacketTask> queue = new LinkedBlockingQueue<>(4096);
                    queues.add(queue);
                    Worker worker = new Worker(i, queue, ruleEngine, outputWriter, stats);
                    Thread t = new Thread(worker, "dpi-worker-" + i);
                    workerThreads.add(t);
                    t.start();
                }

                LoadBalancer loadBalancer = new LoadBalancer(
                        reader, connectionTable, queues, outputWriter, stats);
                Thread loadBalancerThread = new Thread(loadBalancer, "dpi-load-balancer");
                loadBalancerThread.start();

                loadBalancerThread.join();
                for (Thread t : workerThreads) {
                    t.join();
                }
                writerThread.join();

                if (loadBalancer.getFailure() != null) {
                    throw loadBalancer.getFailure();
                }
                if (outputWriter.getFailure() != null) {
                    throw outputWriter.getFailure();
                }
            }
        }
        return stats;
    }

    public ConnectionTable getConnectionTable() {
        return connectionTable;
    }
}
