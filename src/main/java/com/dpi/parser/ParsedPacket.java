package com.dpi.parser;

/**
 * The fields a DPI engine actually needs out of a packet: enough of the
 * header stack to build a connection key, plus a pointer to where the
 * transport-layer payload starts (where TLS ClientHello / SNI would live).
 */
public final class ParsedPacket {

    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    private final boolean valid;
    private final String srcIp;
    private final String dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;
    private final byte[] frame;
    private final int payloadOffset;
    private final int payloadLength;
    private final boolean synFlag;

    private ParsedPacket(boolean valid, String srcIp, String dstIp, int srcPort, int dstPort,
                          int protocol, byte[] frame, int payloadOffset, int payloadLength,
                          boolean synFlag) {
        this.valid = valid;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.frame = frame;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
        this.synFlag = synFlag;
    }

    public static ParsedPacket invalid(byte[] frame) {
        return new ParsedPacket(false, null, null, 0, 0, -1, frame, 0, 0, false);
    }

    public static ParsedPacket of(String srcIp, String dstIp, int srcPort, int dstPort,
                                   int protocol, byte[] frame, int payloadOffset,
                                   int payloadLength, boolean synFlag) {
        return new ParsedPacket(true, srcIp, dstIp, srcPort, dstPort, protocol, frame,
                payloadOffset, payloadLength, synFlag);
    }

    public boolean isValid() {
        return valid;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public byte[] getFrame() {
        return frame;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public boolean isSynFlag() {
        return synFlag;
    }

    public boolean hasPayload() {
        return payloadLength > 0;
    }
}
