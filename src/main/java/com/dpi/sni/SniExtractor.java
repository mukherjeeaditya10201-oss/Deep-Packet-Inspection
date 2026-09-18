package com.dpi.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Pulls the Server Name Indication (SNI) hostname out of a TLS
 * ClientHello, when one happens to sit in the given payload.
 *
 * This is a "single packet" extractor: it does not perform TCP stream
 * reassembly, so a ClientHello split unusually across multiple TCP
 * segments will simply not be seen - the same simplification the
 * original engine made. In practice the ClientHello (and its SNI
 * extension) almost always lands in the very first data segment of a
 * TLS connection, which is the case this is built to catch.
 */
public final class SniExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_TYPE_SNI = 0x0000;
    private static final int SNI_NAME_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
    }

    public static Optional<String> extract(byte[] frame, int offset, int length) {
        try {
            if (length < 5) {
                return Optional.empty();
            }
            int pos = offset;
            int limit = offset + length;

            int contentType = u8(frame, pos);
            if (contentType != CONTENT_TYPE_HANDSHAKE) {
                return Optional.empty();
            }
            // major/minor TLS version at pos+1..pos+2 - not needed.
            int recordLength = u16(frame, pos + 3);
            pos += 5;
            if (pos + recordLength > limit || recordLength < 4) {
                // Truncated / not what we're expecting - bail out quietly.
                recordLength = Math.min(recordLength, limit - pos);
                if (recordLength < 4) {
                    return Optional.empty();
                }
            }

            int handshakeType = u8(frame, pos);
            if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
                return Optional.empty();
            }
            int handshakeLength = u24(frame, pos + 1);
            pos += 4;
            int handshakeEnd = Math.min(limit, pos + handshakeLength);

            // ClientHello body: version(2) + random(32) + session_id
            pos += 2 + 32;
            if (pos >= handshakeEnd) {
                return Optional.empty();
            }
            int sessionIdLen = u8(frame, pos);
            pos += 1 + sessionIdLen;

            int cipherSuitesLen = u16(frame, pos);
            pos += 2 + cipherSuitesLen;

            int compressionMethodsLen = u8(frame, pos);
            pos += 1 + compressionMethodsLen;

            if (pos + 2 > handshakeEnd) {
                return Optional.empty(); // no extensions present
            }
            int extensionsLen = u16(frame, pos);
            pos += 2;
            int extensionsEnd = Math.min(handshakeEnd, pos + extensionsLen);

            while (pos + 4 <= extensionsEnd) {
                int extType = u16(frame, pos);
                int extLen = u16(frame, pos + 2);
                int extDataStart = pos + 4;
                if (extType == EXTENSION_TYPE_SNI) {
                    Optional<String> name = parseSniExtension(frame, extDataStart, extLen);
                    if (name.isPresent()) {
                        return name;
                    }
                }
                pos = extDataStart + extLen;
            }
            return Optional.empty();
        } catch (RuntimeException malformedOrTruncated) {
            return Optional.empty();
        }
    }

    private static Optional<String> parseSniExtension(byte[] frame, int start, int len) {
        if (len < 5) {
            return Optional.empty();
        }
        int pos = start;
        int end = start + len;
        int serverNameListLen = u16(frame, pos);
        pos += 2;
        int listEnd = Math.min(end, pos + serverNameListLen);

        while (pos + 3 <= listEnd) {
            int nameType = u8(frame, pos);
            int nameLen = u16(frame, pos + 1);
            int nameStart = pos + 3;
            if (nameStart + nameLen > listEnd) {
                break;
            }
            if (nameType == SNI_NAME_TYPE_HOSTNAME) {
                return Optional.of(new String(frame, nameStart, nameLen, StandardCharsets.US_ASCII));
            }
            pos = nameStart + nameLen;
        }
        return Optional.empty();
    }

    private static int u8(byte[] b, int offset) {
        return b[offset] & 0xFF;
    }

    private static int u16(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    private static int u24(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 16) | ((b[offset + 1] & 0xFF) << 8) | (b[offset + 2] & 0xFF);
    }
}
