package dpi.model;

/**
 * Parsed headers plus a reference to the original raw data for writing.
 */
public record ParsedPacket(
        FiveTuple fiveTuple,
        int ipHeaderLength,
        int transportHeaderLength,
        int payloadOffset,
        int payloadLength,
        byte[] rawData,
        long timestampSec,
        long timestampUsec
) {
    public boolean hasPayload() {
        return payloadLength > 0;
    }

    public RawPacket toRawPacket() {
        return new RawPacket(rawData, timestampSec, timestampUsec);
    }
}