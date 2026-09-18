package com.dpi.engine;

import com.dpi.connection.Connection;
import com.dpi.parser.ParsedPacket;
import com.dpi.pcap.RawPacket;

/**
 * Everything a fast-path worker thread needs to process one packet:
 * the original captured bytes (for writing to the output file), the
 * already-parsed headers, and the connection it belongs to.
 *
 * A null instance is used as the "poison pill" that tells a worker its
 * input queue is finished.
 */
public final class PacketTask {

    /**
     * Sentinel placed on a worker's queue to signal "no more packets are
     * coming for you". BlockingQueue implementations disallow null
     * elements, so a dedicated marker instance is used instead of null.
     */
    public static final PacketTask POISON_PILL = new PacketTask(null, null, null);

    private final RawPacket raw;
    private final ParsedPacket parsed;
    private final Connection connection;

    public PacketTask(RawPacket raw, ParsedPacket parsed, Connection connection) {
        this.raw = raw;
        this.parsed = parsed;
        this.connection = connection;
    }

    public boolean isPoisonPill() {
        return this == POISON_PILL;
    }

    public RawPacket getRaw() {
        return raw;
    }

    public ParsedPacket getParsed() {
        return parsed;
    }

    public Connection getConnection() {
        return connection;
    }
}
