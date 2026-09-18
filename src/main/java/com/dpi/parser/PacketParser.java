package com.dpi.parser;

/**
 * Minimal, dependency-free header parser: Ethernet -> IPv4 -> TCP/UDP.
 * Anything else (ARP, IPv6, VLAN tags we don't bother unwrapping, etc.)
 * comes back as an "invalid" ParsedPacket and is passed straight through
 * by the engine rather than inspected.
 */
public final class PacketParser {

    private static final int ETHERNET_HEADER_LEN = 14;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_VLAN = 0x8100;

    private PacketParser() {
    }

    public static ParsedPacket parse(byte[] frame) {
        try {
            if (frame.length < ETHERNET_HEADER_LEN + 20) {
                return ParsedPacket.invalid(frame);
            }

            int offset = 12; // skip dst MAC(6) + src MAC(6)
            int etherType = u16(frame, offset);
            offset += 2;

            // Unwrap a single 802.1Q VLAN tag if present.
            if (etherType == ETHERTYPE_VLAN) {
                if (frame.length < offset + 4 + 20) {
                    return ParsedPacket.invalid(frame);
                }
                offset += 2; // tag control info
                etherType = u16(frame, offset);
                offset += 2;
            }

            if (etherType != ETHERTYPE_IPV4) {
                return ParsedPacket.invalid(frame);
            }

            int ipStart = offset;
            int versionAndIhl = frame[ipStart] & 0xFF;
            int version = versionAndIhl >> 4;
            int ihl = (versionAndIhl & 0x0F) * 4;
            if (version != 4 || ihl < 20 || frame.length < ipStart + ihl) {
                return ParsedPacket.invalid(frame);
            }

            int totalLength = u16(frame, ipStart + 2);
            int protocol = frame[ipStart + 9] & 0xFF;
            String srcIp = ipToString(frame, ipStart + 12);
            String dstIp = ipToString(frame, ipStart + 16);

            int transportStart = ipStart + ihl;
            int ipPayloadEnd = Math.min(frame.length, ipStart + Math.max(totalLength, ihl));

            if (protocol == ParsedPacket.PROTO_TCP) {
                if (frame.length < transportStart + 20) {
                    return ParsedPacket.invalid(frame);
                }
                int srcPort = u16(frame, transportStart);
                int dstPort = u16(frame, transportStart + 2);
                int dataOffsetWords = (frame[transportStart + 12] & 0xF0) >> 4;
                int tcpHeaderLen = dataOffsetWords * 4;
                boolean syn = (frame[transportStart + 13] & 0x02) != 0;
                if (tcpHeaderLen < 20 || frame.length < transportStart + tcpHeaderLen) {
                    return ParsedPacket.invalid(frame);
                }
                int payloadOffset = transportStart + tcpHeaderLen;
                int payloadLength = Math.max(0, ipPayloadEnd - payloadOffset);
                return ParsedPacket.of(srcIp, dstIp, srcPort, dstPort, protocol, frame,
                        payloadOffset, payloadLength, syn);
            } else if (protocol == ParsedPacket.PROTO_UDP) {
                if (frame.length < transportStart + 8) {
                    return ParsedPacket.invalid(frame);
                }
                int srcPort = u16(frame, transportStart);
                int dstPort = u16(frame, transportStart + 2);
                int payloadOffset = transportStart + 8;
                int payloadLength = Math.max(0, ipPayloadEnd - payloadOffset);
                return ParsedPacket.of(srcIp, dstIp, srcPort, dstPort, protocol, frame,
                        payloadOffset, payloadLength, false);
            }

            // Other IP protocols (ICMP, etc.) - not tracked as connections.
            return ParsedPacket.invalid(frame);
        } catch (RuntimeException malformed) {
            // Never let a malformed/truncated packet crash the engine -
            // treat it like anything else we don't understand.
            return ParsedPacket.invalid(frame);
        }
    }

    private static int u16(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    private static String ipToString(byte[] b, int offset) {
        return (b[offset] & 0xFF) + "." + (b[offset + 1] & 0xFF) + "."
                + (b[offset + 2] & 0xFF) + "." + (b[offset + 3] & 0xFF);
    }
}
