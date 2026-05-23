package dpi.io;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import dpi.model.RawPacket;

/**
 * Reads PCAP capture files using little-endian header parsing.
 */
public class PcapReader implements Closeable {
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private static final int MAGIC_NUMBER = 0xa1b2c3d4;
    private static final int MAGIC_NUMBER_SWAPPED = 0xd4c3b2a1;

    private final InputStream in;
    private final ByteOrder byteOrder;
    private final int snaplen;
    private final int network;

    /**
     * Opens a PCAP input stream and validates the global header.
     */
    public PcapReader(InputStream in) throws IOException {
        this.in = in;
        byte[] global = readFully(GLOBAL_HEADER_SIZE);
        ByteBuffer buf = ByteBuffer.wrap(global);
        int magic = buf.getInt();
        if (magic == MAGIC_NUMBER) {
            this.byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magic == MAGIC_NUMBER_SWAPPED) {
            this.byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            throw new IOException("Invalid PCAP magic number: " + Integer.toHexString(magic));
        }
        buf.order(this.byteOrder);
        buf.getShort(); // major version
        buf.getShort(); // minor version
        buf.getInt();   // thiszone
        buf.getInt();   // sigfigs
        this.snaplen = buf.getInt();
        this.network = buf.getInt();
        if (this.network != 1) {
            throw new IOException("Unsupported network type: " + this.network);
        }
    }

    private byte[] readFully(int len) throws IOException {
        byte[] b = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(b, off, len - off);
            if (r == -1) throw new EOFException("Unexpected EOF");
            off += r;
        }
        return b;
    }

    /**
     * Reads the next packet. Returns null on clean EOF.
     */
    public RawPacket readPacket() throws IOException {
        byte[] header;
        try {
            header = readFully(PACKET_HEADER_SIZE);
        } catch (EOFException e) {
            return null; // clean end of file
        }
        ByteBuffer buf = ByteBuffer.wrap(header).order(byteOrder);
        long tsSec = Integer.toUnsignedLong(buf.getInt());
        long tsUsec = Integer.toUnsignedLong(buf.getInt());
        int inclLen = buf.getInt();
        int origLen = buf.getInt();
        if (inclLen < 0 || inclLen > snaplen) {
            throw new IOException("Invalid packet length: " + inclLen);
        }
        byte[] data = readFully(inclLen);
        return new RawPacket(data, tsSec, tsUsec);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
