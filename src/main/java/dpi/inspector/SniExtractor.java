package dpi.inspector;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello handshakes.
 */
public class SniExtractor {

    /**
     * Attempts to parse SNI from a TCP payload destined for port 443.
     *
     * @param payload  full packet byte array
     * @param offset   start of payload within the array
     * @param length   length of payload
     * @param dstPort  destination port (must be 443)
     * @return SNI string if found
     */
    public static Optional<String> extract(byte[] payload, int offset, int length, int dstPort) {
        if (dstPort != 443 || length < 6) return Optional.empty();
        int end = offset + length;

        if ((payload[offset] & 0xFF) != 0x16) return Optional.empty(); // handshake record
        if ((payload[offset + 5] & 0xFF) != 0x01) return Optional.empty(); // Client Hello

        int pos = offset + 9; // start of Client Hello body

        if (pos + 2 > end) return Optional.empty();
        pos += 2; // client version

        if (pos + 32 > end) return Optional.empty();
        pos += 32; // random

        if (pos + 1 > end) return Optional.empty();
        int sessionIdLen = payload[pos++] & 0xFF;
        if (pos + sessionIdLen > end) return Optional.empty();
        pos += sessionIdLen;

        if (pos + 2 > end) return Optional.empty();
        int cipherSuitesLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2 + cipherSuitesLen;
        if (pos > end) return Optional.empty();

        if (pos + 1 > end) return Optional.empty();
        int compressionLen = payload[pos++] & 0xFF;
        pos += compressionLen;
        if (pos > end) return Optional.empty();

        if (pos + 2 > end) return Optional.empty();
        int extensionsLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
        pos += 2;
        int extensionsEnd = Math.min(end, pos + extensionsLen);

        while (pos + 4 <= extensionsEnd) {
            int extType = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
            int extLen = ((payload[pos + 2] & 0xFF) << 8) | (payload[pos + 3] & 0xFF);
            pos += 4;
            if (pos + extLen > extensionsEnd) break;

            if (extType == 0x0000) { // SNI
                if (extLen < 5) break;
                pos += 2; // skip SNI list length
                int sniType = payload[pos++] & 0xFF;
                if (sniType != 0x00) break;
                int sniLen = ((payload[pos] & 0xFF) << 8) | (payload[pos + 1] & 0xFF);
                pos += 2;
                if (pos + sniLen > extensionsEnd) break;
                String sni = new String(payload, pos, sniLen, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }
            pos += extLen;
        }
        return Optional.empty();
    }
}