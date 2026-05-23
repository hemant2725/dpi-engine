package dpi.model;

import java.util.Objects;

/**
 * Immutable 5-tuple flow identifier with bidirectional normalization.
 * The smaller IP (and then smaller port) is always stored as "src"
 * so both directions of a flow map to the same key.
 */
public final class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final short protocol;

    /**
     * Creates a normalized 5-tuple.
     *
     * @param srcIp    source IP in network byte order (big-endian int)
     * @param dstIp    destination IP
     * @param srcPort  source port (unsigned 16-bit)
     * @param dstPort  destination port
     * @param protocol IP protocol number (e.g., 6=TCP, 17=UDP)
     */
    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, short protocol) {
        if (Integer.compareUnsigned(srcIp, dstIp) > 0 ||
            (srcIp == dstIp && Integer.compareUnsigned(srcPort, dstPort) > 0)) {
            this.srcIp = dstIp;
            this.dstIp = srcIp;
            this.srcPort = dstPort;
            this.dstPort = srcPort;
        } else {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
        this.protocol = protocol;
    }

    public int srcIp() { return srcIp; }
    public int dstIp() { return dstIp; }
    public int srcPort() { return srcPort; }
    public int dstPort() { return dstPort; }
    public short protocol() { return protocol; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple other)) return false;
        return srcIp == other.srcIp && dstIp == other.dstIp &&
               srcPort == other.srcPort && dstPort == other.dstPort &&
               protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    /**
     * Converts a big-endian int IP to dotted-decimal notation.
     */
    public static String ipToString(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip >>> 24) & 0xFF,
                (ip >>> 16) & 0xFF,
                (ip >>> 8) & 0xFF,
                ip & 0xFF);
    }

    @Override
    public String toString() {
        return String.format("%s:%d <-> %s:%d proto=%d",
                ipToString(srcIp), srcPort & 0xFFFF,
                ipToString(dstIp), dstPort & 0xFFFF,
                protocol);
    }
}