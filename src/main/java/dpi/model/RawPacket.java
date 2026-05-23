package dpi.model;

/**
 * Raw packet bytes with PCAP timestamp.
 */
public record RawPacket(byte[] data, long timestampSec, long timestampUsec) {
    /**
     * A poison pill has null or empty data and signals pipeline shutdown.
     */
    public boolean isPoisonPill() {
        return data == null || data.length == 0;
    }
}