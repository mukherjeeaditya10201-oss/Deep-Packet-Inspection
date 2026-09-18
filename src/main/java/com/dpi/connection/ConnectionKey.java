package com.dpi.connection;

import java.util.Objects;

/**
 * Identifies a connection by its 5-tuple (src IP/port, dst IP/port, protocol),
 * normalized so that packets flowing in either direction of the same
 * conversation map to the same key and therefore the same worker thread.
 */
public final class ConnectionKey {

    private final String ipA;
    private final int portA;
    private final String ipB;
    private final int portB;
    private final int protocol;

    private ConnectionKey(String ipA, int portA, String ipB, int portB, int protocol) {
        this.ipA = ipA;
        this.portA = portA;
        this.ipB = ipB;
        this.portB = portB;
        this.protocol = protocol;
    }

    public static ConnectionKey of(String srcIp, int srcPort, String dstIp, int dstPort, int protocol) {
        // Order the two endpoints canonically so (A->B) and (B->A) collapse
        // to the same key.
        int cmp = srcIp.compareTo(dstIp);
        if (cmp > 0 || (cmp == 0 && srcPort > dstPort)) {
            return new ConnectionKey(dstIp, dstPort, srcIp, srcPort, protocol);
        }
        return new ConnectionKey(srcIp, srcPort, dstIp, dstPort, protocol);
    }

    public int getProtocol() {
        return protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConnectionKey)) return false;
        ConnectionKey that = (ConnectionKey) o;
        return portA == that.portA && portB == that.portB && protocol == that.protocol
                && ipA.equals(that.ipA) && ipB.equals(that.ipB);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ipA, portA, ipB, portB, protocol);
    }

    @Override
    public String toString() {
        return ipA + ":" + portA + " <-> " + ipB + ":" + portB + " (proto " + protocol + ")";
    }

    /**
     * A stable non-negative bucket number, used by the load balancer to
     * assign every packet of a given connection to the same worker thread.
     */
    public int bucket(int numBuckets) {
        return (hashCode() & Integer.MAX_VALUE) % numBuckets;
    }
}
