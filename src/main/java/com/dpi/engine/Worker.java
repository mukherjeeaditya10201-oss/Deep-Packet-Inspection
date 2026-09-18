package com.dpi.engine;

import com.dpi.connection.Connection;
import com.dpi.parser.ParsedPacket;
import com.dpi.rules.Rule;
import com.dpi.rules.RuleEngine;
import com.dpi.sni.SniExtractor;
import com.dpi.stats.DpiStats;

import java.util.Optional;
import java.util.concurrent.BlockingQueue;

/**
 * The "postman": pulls packets belonging to its assigned connections off
 * its own queue, inspects the header (and, once seen, the SNI) and applies
 * the rule engine's verdict. All packets of a given connection always land
 * on the same worker (see ConnectionKey#bucket), so no locking is needed
 * around a connection's mutable state.
 */
public final class Worker implements Runnable {

    private final int id;
    private final BlockingQueue<PacketTask> queue;
    private final RuleEngine ruleEngine;
    private final OutputWriter outputWriter;
    private final DpiStats stats;

    public Worker(int id, BlockingQueue<PacketTask> queue, RuleEngine ruleEngine,
                   OutputWriter outputWriter, DpiStats stats) {
        this.id = id;
        this.queue = queue;
        this.ruleEngine = ruleEngine;
        this.outputWriter = outputWriter;
        this.stats = stats;
    }

    @Override
    public void run() {
        try {
            while (true) {
                PacketTask task = queue.take();
                if (task.isPoisonPill()) {
                    // This worker's share of the capture is done.
                    return;
                }
                process(task);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void process(PacketTask task) {
        ParsedPacket packet = task.getParsed();
        Connection conn = task.getConnection();

        stats.incrementTotal();
        conn.recordPacket(task.getRaw().getData().length);

        if (packet.getProtocol() == ParsedPacket.PROTO_TCP && conn.getSni() == null
                && packet.hasPayload()) {
            Optional<String> sni = SniExtractor.extract(
                    packet.getFrame(), packet.getPayloadOffset(), packet.getPayloadLength());
            sni.ifPresent(conn::setSni);
        }

        Rule verdict = ruleEngine.decide(conn, packet);
        outputWriter.submit(task.getRaw().getSequence(), task.getRaw(), !verdict.isDrop());
    }

    public int getId() {
        return id;
    }
}
