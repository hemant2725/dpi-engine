package dpi.io;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import dpi.model.RawPacket;

/**
 * Writes packets to a PCAP file with little-endian headers.
 */
public class PcapWriter implements Closeable {
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int MAGIC_NUMBER = 0xa1b2c3d4;

    private final OutputStream out;
    private final ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    private boolean headerWritten;

    public PcapWriter(OutputStream out) {
        this.out = out;
    }

    /**
     * Writes the 24-byte PCAP global header.
     */
    public void writeGlobalHeader() throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(GLOBAL_HEADER_SIZE).order(byteOrder);
        buf.putInt(MAGIC_NUMBER);
        buf.putShort((short) 2);   // major
        buf.putShort((short) 4);   // minor
        buf.putInt(0);             // thiszone
        buf.putInt(0);             // sigfigs
        buf.putInt(65535);         // snaplen
        buf.putInt(1);             // Ethernet
        out.write(buf.array());
        headerWritten = true;
    }

    /**
     * Writes a single packet with its 16-byte header.
     */
    public void writePacket(RawPacket packet) throws IOException {
        if (!headerWritten) writeGlobalHeader();
        byte[] data = packet.data();
        int len = data.length;
        ByteBuffer hdr = ByteBuffer.allocate(16).order(byteOrder);
        hdr.putInt((int) packet.timestampSec());
        hdr.putInt((int) packet.timestampUsec());
        hdr.putInt(len);
        hdr.putInt(len); // orig_len = incl_len
        out.write(hdr.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}