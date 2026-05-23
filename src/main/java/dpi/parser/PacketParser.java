package dpi.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import dpi.model.FiveTuple;
import dpi.model.ParsedPacket;
import dpi.model.RawPacket;

/**
 * Parses Ethernet → IPv4 → TCP/UDP headers using big-endian reads.
 */
public class PacketParser {

    /**
     * Parses a raw packet into structured fields.
     *
     * @return parsed packet or null if not IPv4 or truncated
     */
    public ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data();
        if (data == null || data.length < 14) return null;

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int etherType = buf.getShort(12) & 0xFFFF;
        if (etherType != 0x0800) return null; // not IPv4

        int ipOffset = 14;
        if (data.length < ipOffset + 20) return null;

        int versionIhl = buf.get(ipOffset) & 0xFF;
        int ihl = versionIhl & 0x0F;
        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || data.length < ipOffset + ipHeaderLen) return null;

        int protocol = buf.get(ipOffset + 9) & 0xFF;
        int srcIp = buf.getInt(ipOffset + 12);
        int dstIp = buf.getInt(ipOffset + 16);

        int transportOffset = ipOffset + ipHeaderLen;
        int srcPort = 0, dstPort = 0, transportHeaderLen = 0;

        if (protocol == 6) { // TCP
            if (data.length < transportOffset + 20) return null;
            srcPort = buf.getShort(transportOffset) & 0xFFFF;
            dstPort = buf.getShort(transportOffset + 2) & 0xFFFF;
            int dataOffset = (buf.get(transportOffset + 12) >> 4) & 0x0F;
            transportHeaderLen = dataOffset * 4;
            if (transportHeaderLen < 20 || data.length < transportOffset + transportHeaderLen) return null;
        } else if (protocol == 17) { // UDP
            if (data.length < transportOffset + 8) return null;
            srcPort = buf.getShort(transportOffset) & 0xFFFF;
            dstPort = buf.getShort(transportOffset + 2) & 0xFFFF;
            transportHeaderLen = 8;
        } else {
            return null; // unsupported transport
        }

        int payloadOffset = transportOffset + transportHeaderLen;
        int payloadLength = Math.max(0, data.length - payloadOffset);

        FiveTuple tuple = new FiveTuple(srcIp, dstIp, srcPort, dstPort, (short) protocol);
        return new ParsedPacket(tuple, ipHeaderLen, transportHeaderLen,
                payloadOffset, payloadLength, data, raw.timestampSec(), raw.timestampUsec());
    }
}