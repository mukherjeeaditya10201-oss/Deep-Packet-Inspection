package com.dpi.connection;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;

/**
 * All known connections, keyed by their normalized 5-tuple. Safe for
 * concurrent lookups/creation from the load balancer and worker threads;
 * once created, a given Connection object is only ever mutated by the one
 * worker thread its packets are routed to.
 */
public final class ConnectionTable {

    private final ConcurrentHashMap<ConnectionKey, Connection> connections = new ConcurrentHashMap<>();

    public Connection getOrCreate(ConnectionKey key) {
        return connections.computeIfAbsent(key, Connection::new);
    }

    public int size() {
        return connections.size();
    }

    public Collection<Connection> all() {
        return connections.values();
    }
}
