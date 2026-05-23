package dpi;

import dpi.engine.*;
import dpi.inspector.HttpHostExtractor;
import dpi.inspector.SniExtractor;
import dpi.io.PcapReader;
import dpi.io.PcapWriter;
import dpi.model.*;
import dpi.parser.PacketParser;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

/**
 * Single-threaded DPI pipeline: read → parse → classify → block → write → report.
 */
public class DpiSimple {
    private final RuleManager ruleManager;
    private final ConnectionTracker tracker;
    private final PacketParser parser;
    private final PcapReader reader;
    private final PcapWriter writer;

    private long totalPackets;
    private long totalBytes;
    private long tcpPackets;
    private long udpPackets;
    private long forwarded;
    private long dropped;
    private final Map<AppType, Long> appCounts = new HashMap<>();
    private final Set<String> detectedSnis = new LinkedHashSet<>();

    public DpiSimple(String inputPath, String outputPath, RuleManager rules) throws IOException {
        this.ruleManager = rules;
        this.tracker = new ConnectionTracker();
        this.parser = new PacketParser();
        this.reader = new PcapReader(new FileInputStream(inputPath));
        this.writer = new PcapWriter(new FileOutputStream(outputPath));
        this.writer.writeGlobalHeader();
    }

    /**
     * Runs the single-threaded processing loop.
     */
    public void run() throws IOException {
        RawPacket raw;
        while ((raw = reader.readPacket()) != null) {
            totalPackets++;
            totalBytes += raw.data().length;

            ParsedPacket parsed = parser.parse(raw);
            if (parsed == null) {
                // Non-IPv4 / unknown EtherType — forward untouched
                writer.writePacket(raw);
                forwarded++;
                continue;
            }

            FiveTuple tuple = parsed.fiveTuple();
            if (tuple.protocol() == 6) tcpPackets++;
            else if (tuple.protocol() == 17) udpPackets++;

            Flow flow = tracker.getOrCreate(tuple);
            flow.incrementPacketCount();
            flow.addByteCount(raw.data().length);

            // Extract SNI or HTTP Host
            String host = null;
            if (parsed.hasPayload()) {
                int dstPort = tuple.dstPort() & 0xFFFF;
                var sni = SniExtractor.extract(parsed.rawData(), parsed.payloadOffset(), parsed.payloadLength(), dstPort);
                if (sni.isPresent()) {
                    host = sni.get();
                    flow.setSni(host);
                } else {
                    var http = HttpHostExtractor.extract(parsed.rawData(), parsed.payloadOffset(), parsed.payloadLength());
                    if (http.isPresent()) {
                        host = http.get();
                        flow.setSni(host);
                    }
                }
            }

            // Classify
            int dstPort = tuple.dstPort() & 0xFFFF;
            AppType app = AppClassifier.classify(host, dstPort);
            if (flow.getAppType() == AppType.UNKNOWN || flow.getAppType() == AppType.HTTP || flow.getAppType() == AppType.HTTPS) {
                flow.setAppType(app);
            }

            // Apply rules
            boolean blocked = ruleManager.isBlocked(tuple.srcIp(), flow.getAppType(), flow.getSni());
            if (blocked) {
                flow.setBlocked(true);
                dropped++;
            } else {
                writer.writePacket(raw);
                forwarded++;
            }

            appCounts.merge(flow.getAppType(), 1L, Long::sum);
            if (flow.getSni() != null && !flow.getSni().isEmpty()) {
                detectedSnis.add(flow.getSni() + " -> " + flow.getAppType());
            }
        }

        reader.close();
        writer.close();
        printReport();
    }

    private void printReport() {
        System.out.println("========================================");
        System.out.println("         DPI ENGINE (Java)");
        System.out.println("========================================");
        System.out.printf(" Total Packets:    %-19d%n", totalPackets);
        System.out.printf(" Total Bytes:      %-19d%n", totalBytes);
        System.out.printf(" TCP Packets:      %-19d%n", tcpPackets);
        System.out.printf(" UDP Packets:      %-19d%n", udpPackets);
        System.out.println("----------------------------------------");
        System.out.printf(" Forwarded:        %-19d%n", forwarded);
        System.out.printf(" Dropped:          %-19d%n", dropped);
        System.out.println("----------------------------------------");
        System.out.println(" APPLICATION BREAKDOWN");

        var sorted = appCounts.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .toList();

        for (var e : sorted) {
            AppType app = e.getKey();
            long count = e.getValue();
            double pct = totalPackets > 0 ? (count * 100.0 / totalPackets) : 0;
            String mark = ruleManager.isAppBlocked(app) ? " (BLOCKED)" : "";
            int hashes = Math.min(20, (int) Math.round(pct / 5.0));
            String bar = "#".repeat(hashes);
            System.out.printf(" %-9s %3d %5.1f%% %-16s%n", app, count, pct, bar + mark);
        }

        System.out.println("----------------------------------------");
        System.out.println(" DETECTED SNIs");
        for (String s : detectedSnis) {
            System.out.printf(" %s%n", s);
        }
        System.out.println("========================================");
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: java -jar dpi.jar input.pcap output.pcap [options]");
            System.exit(1);
        }
        String input = args[0];
        String output = args[1];
        List<String> blockApps = new ArrayList<>();
        List<String> blockIps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-app" -> { if (i + 1 < args.length) blockApps.add(args[++i]); }
                case "--block-ip" -> { if (i + 1 < args.length) blockIps.add(args[++i]); }
                case "--block-domain" -> { if (i + 1 < args.length) blockDomains.add(args[++i]); }
            }
        }

        RuleManager rules = new RuleManager(blockDomains);
        for (String ip : blockIps) rules.blockIp(ip);
        for (String a : blockApps) {
            try {
                rules.blockApp(AppType.valueOf(a.toUpperCase()));
            } catch (IllegalArgumentException ex) {
                System.err.println("Unknown app: " + a);
            }
        }

        new DpiSimple(input, output, rules).run();
    }
}


