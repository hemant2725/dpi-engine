package dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import dpi.io.PcapWriter;
import dpi.model.RawPacket;

/**
 * Generates a synthetic PCAP with TLS (SNI), HTTP, and DNS traffic for testing.
 */
public class PcapGenerator {

    public static void main(String[] args) throws IOException {
        String out = args.length > 0 ? args[0] : "test.pcap";
        List<RawPacket> packets = new ArrayList<>();

        packets.add(createTls("192.168.1.10", "142.250.80.46", 443, "www.youtube.com"));
        packets.add(createTls("192.168.1.11", "157.240.192.35", 443, "www.facebook.com"));
        packets.add(createTls("192.168.1.12", "142.250.80.46", 443, "www.google.com"));
        packets.add(createHttp("192.168.1.13", "93.184.216.34", 80, "example.com"));
        packets.add(createUdp("192.168.1.14", "8.8.8.8", 53, new byte[]{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));

        // Random TCP noise
        for (int i = 0; i < 5; i++) {
            packets.add(createTcp("192.168.1." + (20 + i), "10.0.0." + i, 12345, 8080, new byte[]{0x01, 0x02, 0x03}));
        }

        try (PcapWriter w = new PcapWriter(new FileOutputStream(out))) {
            w.writeGlobalHeader();
            for (RawPacket p : packets) w.writePacket(p);
        }
        System.out.println("Generated " + packets.size() + " packets to " + out);
    }

    private static RawPacket createTls(String srcIp, String dstIp, int dstPort, String sni) {
        return buildTcp(srcIp, dstIp, 54321, dstPort, buildTlsPayload(sni));
    }

    private static RawPacket createHttp(String srcIp, String dstIp, int dstPort, String host) {
        String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
        return buildTcp(srcIp, dstIp, 54322, dstPort, req.getBytes());
    }

    private static RawPacket createUdp(String srcIp, String dstIp, int dstPort, byte[] payload) {
        return buildUdp(srcIp, dstIp, 12345, dstPort, payload);
    }

    private static RawPacket createTcp(String srcIp, String dstIp, int srcPort, int dstPort, byte[] payload) {
        return buildTcp(srcIp, dstIp, srcPort, dstPort, payload);
    }

    private static byte[] buildTlsPayload(String sni) {
        byte[] sniBytes = sni.getBytes();
        int sniExtDataLen = 5 + sniBytes.length; // 2 list len + 1 type + 2 len + data
        int extLen = 4 + sniExtDataLen;          // 2 type + 2 ext len + data
        int handshakeBodyLen = 43 + extLen;        // version(2)+random(32)+sess(1)+cipher(4)+comp(2)+extlen(2)+ext
        int recordLen = 4 + handshakeBodyLen;      // handshake type(1)+len(3)+body

        byte[] pkt = new byte[5 + recordLen];
        int p = 0;

        pkt[p++] = 0x16; // handshake
        pkt[p++] = 0x03; pkt[p++] = 0x01; // TLS 1.0 record version
        pkt[p++] = (byte) (recordLen >> 8); pkt[p++] = (byte) recordLen;

        pkt[p++] = 0x01; // Client Hello
        pkt[p++] = (byte) (handshakeBodyLen >> 16);
        pkt[p++] = (byte) (handshakeBodyLen >> 8);
        pkt[p++] = (byte) handshakeBodyLen;

        pkt[p++] = 0x03; pkt[p++] = 0x03; // TLS 1.2
        for (int i = 0; i < 32; i++) pkt[p++] = (byte) (Math.random() * 256); // random
        pkt[p++] = 0x00; // session id len

        pkt[p++] = 0x00; pkt[p++] = 0x02; // cipher suites len
        pkt[p++] = 0x00; pkt[p++] = 0x00; // null cipher

        pkt[p++] = 0x01; pkt[p++] = 0x00; // compression len + null

        // extensions
        pkt[p++] = (byte) (extLen >> 8); pkt[p++] = (byte) extLen;
        // SNI
        pkt[p++] = 0x00; pkt[p++] = 0x00; // ext type
        pkt[p++] = (byte) (sniExtDataLen >> 8); pkt[p++] = (byte) sniExtDataLen;
        pkt[p++] = (byte) ((sniBytes.length + 3) >> 8); pkt[p++] = (byte) (sniBytes.length + 3); // list len
        pkt[p++] = 0x00; // hostname type
        pkt[p++] = (byte) (sniBytes.length >> 8); pkt[p++] = (byte) sniBytes.length;
        System.arraycopy(sniBytes, 0, pkt, p, sniBytes.length);
        return pkt;
    }

    private static RawPacket buildTcp(String srcIp, String dstIp, int srcPort, int dstPort, byte[] payload) {
        int ipHdr = 20, tcpHdr = 20;
        int total = 14 + ipHdr + tcpHdr + payload.length;
        byte[] pkt = new byte[total];

        byte[] dstMac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        byte[] srcMac = {0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb};
        System.arraycopy(dstMac, 0, pkt, 0, 6);
        System.arraycopy(srcMac, 0, pkt, 6, 6);
        pkt[12] = 0x08; pkt[13] = 0x00;

        int ip = 14;
        pkt[ip] = 0x45;
        pkt[ip + 2] = (byte) (total >> 8); pkt[ip + 3] = (byte) total;
        pkt[ip + 4] = 0x00; pkt[ip + 5] = 0x01; // ID
        pkt[ip + 6] = 0x00; pkt[ip + 7] = 0x00; // flags
        pkt[ip + 8] = 0x40; // TTL
        pkt[ip + 9] = 0x06; // TCP
        writeIp(pkt, ip + 12, srcIp);
        writeIp(pkt, ip + 16, dstIp);

        int tcp = ip + ipHdr;
        pkt[tcp] = (byte) (srcPort >> 8); pkt[tcp + 1] = (byte) srcPort;
        pkt[tcp + 2] = (byte) (dstPort >> 8); pkt[tcp + 3] = (byte) dstPort;
        pkt[tcp + 12] = 0x50; // data offset 5
        pkt[tcp + 13] = 0x18; // PSH+ACK

        System.arraycopy(payload, 0, pkt, tcp + tcpHdr, payload.length);
        return new RawPacket(pkt, System.currentTimeMillis() / 1000, 0);
    }

    private static RawPacket buildUdp(String srcIp, String dstIp, int srcPort, int dstPort, byte[] payload) {
        int ipHdr = 20, udpHdr = 8;
        int total = 14 + ipHdr + udpHdr + payload.length;
        byte[] pkt = new byte[total];

        byte[] dstMac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        byte[] srcMac = {0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb};
        System.arraycopy(dstMac, 0, pkt, 0, 6);
        System.arraycopy(srcMac, 0, pkt, 6, 6);
        pkt[12] = 0x08; pkt[13] = 0x00;

        int ip = 14;
        pkt[ip] = 0x45;
        pkt[ip + 2] = (byte) (total >> 8); pkt[ip + 3] = (byte) total;
        pkt[ip + 4] = 0x00; pkt[ip + 5] = 0x01;
        pkt[ip + 6] = 0x00; pkt[ip + 7] = 0x00;
        pkt[ip + 8] = 0x40;
        pkt[ip + 9] = 0x11; // UDP
        writeIp(pkt, ip + 12, srcIp);
        writeIp(pkt, ip + 16, dstIp);

        int udp = ip + ipHdr;
        pkt[udp] = (byte) (srcPort >> 8); pkt[udp + 1] = (byte) srcPort;
        pkt[udp + 2] = (byte) (dstPort >> 8); pkt[udp + 3] = (byte) dstPort;
        int udpLen = udpHdr + payload.length;
        pkt[udp + 4] = (byte) (udpLen >> 8); pkt[udp + 5] = (byte) udpLen;

        System.arraycopy(payload, 0, pkt, udp + udpHdr, payload.length);
        return new RawPacket(pkt, System.currentTimeMillis() / 1000, 0);
    }

    private static void writeIp(byte[] pkt, int off, String ip) {
        String[] pts = ip.split("\\.");
        for (int i = 0; i < 4; i++) pkt[off + i] = (byte) Integer.parseInt(pts[i]);
    }
}
