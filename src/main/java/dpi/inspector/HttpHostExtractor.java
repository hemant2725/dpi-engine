package dpi.inspector;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Host header from HTTP request payloads.
 */
public class HttpHostExtractor {

    private static final String[] METHODS = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "};

    /**
     * Searches for "Host: " in an HTTP payload.
     *
     * @return the Host value, or empty if not HTTP
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (length < 16) return Optional.empty();

        boolean isHttp = false;
        for (String m : METHODS) {
            if (length >= m.length()) {
                boolean match = true;
                for (int i = 0; i < m.length(); i++) {
                    if ((payload[offset + i] & 0xFF) != m.charAt(i)) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    isHttp = true;
                    break;
                }
            }
        }
        if (!isHttp) return Optional.empty();

        String text = new String(payload, offset, length, StandardCharsets.UTF_8);
        int idx = text.indexOf("\r\nHost: ");
        if (idx == -1) idx = text.indexOf("\r\nhost: ");
        if (idx == -1) return Optional.empty();

        int start = idx + 8;
        int end = text.indexOf("\r\n", start);
        if (end == -1) end = text.length();
        return Optional.of(text.substring(start, end).trim());
    }
}