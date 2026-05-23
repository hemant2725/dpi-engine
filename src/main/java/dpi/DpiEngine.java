package dpi;

import dpi.engine.*;
import dpi.io.PcapReader;
import dpi.io.PcapWriter;
import dpi.model.*;
import dpi.parser.PacketParser;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multi-threaded DPI pipeline with Reader → LB → FastPath → Writer.
 * Consistent hashing ensures flow affinity to a single FastPath thread.
 */
public class DpiEngine {
    private final String inputPath;
    private final String outputPath;
    private final RuleManager ruleManager;
    private final int numLBs;
    private final int fpsPerLb;

    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalBytes = new AtomicLong(0);
    private final AtomicLong tcpPackets = new AtomicLong(0);
    private final AtomicLong udpPackets = new AtomicLong(0);
    private final AtomicLong forwarded = new AtomicLong(0);
    private final AtomicLong dropped = new AtomicLong(0);
    private volatile TrafficReport report;

    public DpiEngine(String inputPath, String outputPath, RuleManager ruleManager, int numLBs, int fpsPerLb) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.ruleManager = ruleManager;
        this.numLBs = numLBs;
        this.fpsPerLb = fpsPerLb;
    }

    public void run() throws IOException, InterruptedException {
        int numFPs = numLBs * fpsPerLb;

        @SuppressWarnings("unchecked")
        ThreadSafeQueue<ParsedPacket>[] lbQueues = (ThreadSafeQueue<ParsedPacket>[]) new ThreadSafeQueue<?>[numLBs];
        for (int i = 0; i < numLBs; i++) lbQueues[i] = new ThreadSafeQueue<>();

        @SuppressWarnings("unchecked")
        ThreadSafeQueue<ParsedPacket>[][] fpQueues =
                (ThreadSafeQueue<ParsedPacket>[][]) new ThreadSafeQueue<?>[numLBs][fpsPerLb];
        for (int i = 0; i < numLBs; i++) {
            for (int j = 0; j < fpsPerLb; j++) {
                fpQueues[i][j] = new ThreadSafeQueue<>();
            }
        }

        ThreadSafeQueue<RawPacket> outputQueue = new ThreadSafeQueue<>();

        ExecutorService executor = Executors.newFixedThreadPool(1 + numLBs + numFPs + 1);
        CountDownLatch latch = new CountDownLatch(1 + numLBs + numFPs + 1);
        List<FastPath> fastPaths = new ArrayList<>();

        // Reader
        executor.submit(() -> {
            try { readerTask(lbQueues); } finally { latch.countDown(); }
        });

        // Load Balancers
        for (int i = 0; i < numLBs; i++) {
            final int idx = i;
            executor.submit(() -> {
                try { new LoadBalancer(lbQueues[idx], fpQueues[idx], fpsPerLb).run(); }
                catch (Exception ignored) {} finally { latch.countDown(); }
            });
        }

        // FastPaths
        for (int i = 0; i < numLBs; i++) {
            for (int j = 0; j < fpsPerLb; j++) {
                FastPath fp = new FastPath(fpQueues[i][j], outputQueue, ruleManager,
                        i * fpsPerLb + j, forwarded, dropped);
                fastPaths.add(fp);
                executor.submit(() -> { try { fp.run(); } finally { latch.countDown(); } });
            }
        }

        // Writer
        executor.submit(() -> {
            try { writerTask(outputQueue, numFPs); }
            catch (IOException e) { e.printStackTrace(); } finally { latch.countDown(); }
        });

        latch.await();
        executor.shutdown();

        // Aggregate flow tables for report
        Map<AppType, Long> appCounts = new HashMap<>();
        Set<String> detectedSnis = new LinkedHashSet<>();
        for (FastPath fp : fastPaths) {
            for (Map.Entry<FiveTuple, Flow> e : fp.getFlowTable().entrySet()) {
                Flow f = e.getValue();
                appCounts.merge(f.getAppType(), f.getPacketCount(), Long::sum);
                if (f.getSni() != null && !f.getSni().isEmpty()) {
                    detectedSnis.add(f.getSni() + " -> " + f.getAppType());
                }
            }
        }
        report = ReportBuilder.build(
                totalPackets.get(),
                totalBytes.get(),
                tcpPackets.get(),
                udpPackets.get(),
                forwarded.get(),
                dropped.get(),
                appCounts,
                detectedSnis,
                ruleManager
        );
        printReport(appCounts, detectedSnis);
    }

    public TrafficReport getReport() {
        return report;
    }

    private void readerTask(ThreadSafeQueue<ParsedPacket>[] lbQueues) {
        try (PcapReader reader = new PcapReader(new FileInputStream(inputPath))) {
            PacketParser parser = new PacketParser();
            RawPacket raw;
            while ((raw = reader.readPacket()) != null) {
                totalPackets.incrementAndGet();
                totalBytes.addAndGet(raw.data().length);
                ParsedPacket parsed = parser.parse(raw);
                if (parsed != null) {
                    if (parsed.fiveTuple().protocol() == 6) tcpPackets.incrementAndGet();
                    else if (parsed.fiveTuple().protocol() == 17) udpPackets.incrementAndGet();

                    int hash = parsed.fiveTuple().hashCode();
                    int idx = Math.floorMod(hash, numLBs);
                    lbQueues[idx].put(parsed);
                } else {
                    // route non-IP through LB0 so it still reaches output
                    lbQueues[0].put(new ParsedPacket(null, 0, 0, 0, raw.data().length,
                            raw.data(), raw.timestampSec(), raw.timestampUsec()));
                }
            }
            ParsedPacket poison = new ParsedPacket(null, 0, 0, 0, 0, null, 0, 0);
            for (ThreadSafeQueue<ParsedPacket> q : lbQueues) q.put(poison);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void writerTask(ThreadSafeQueue<RawPacket> outQueue, int numFPs) throws IOException {
        try (PcapWriter writer = new PcapWriter(new FileOutputStream(outputPath))) {
            int poisonsRemaining = numFPs;
            while (poisonsRemaining > 0) {
                RawPacket p = outQueue.take();
                if (p == null || p.data() == null) {
                    poisonsRemaining--;
                } else {
                    writer.writePacket(p);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void printReport(Map<AppType, Long> appCounts, Set<String> detectedSnis) {
        long total = totalPackets.get();
        long bytes = totalBytes.get();
        long tcp = tcpPackets.get();
        long udp = udpPackets.get();
        long fwd = forwarded.get();
        long drp = dropped.get();

        System.out.println("========================================");
        System.out.println("         DPI ENGINE (Java)");
        System.out.println("========================================");
        System.out.printf(" Total Packets:    %-19d%n", total);
        System.out.printf(" Total Bytes:      %-19d%n", bytes);
        System.out.printf(" TCP Packets:      %-19d%n", tcp);
        System.out.printf(" UDP Packets:      %-19d%n", udp);
        System.out.println("----------------------------------------");
        System.out.printf(" Forwarded:        %-19d%n", fwd);
        System.out.printf(" Dropped:          %-19d%n", drp);
        System.out.println("----------------------------------------");
        System.out.println(" APPLICATION BREAKDOWN");

        var sorted = appCounts.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .toList();

        for (var e : sorted) {
            AppType app = e.getKey();
            long count = e.getValue();
            double pct = total > 0 ? (count * 100.0 / total) : 0;
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

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java -jar dpi.jar input.pcap output.pcap [options]");
            System.err.println("  --block-app <App>  --block-ip <IP>  --block-domain <domain>");
            System.err.println("  --lbs <n>  --fps <n>  --simple");
            System.err.println("  --report-json <path>  --report-csv <path>");
            System.exit(1);
        }

        String input = args[0];
        String output = args[1];
        List<String> blockApps = new ArrayList<>();
        List<String> blockIps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        boolean simple = false;
        int lbs = 2;
        int fps = 2;
        String reportJsonPath = null;
        String reportCsvPath = null;

        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-app" -> { if (i + 1 < args.length) blockApps.add(args[++i]); }
                case "--block-ip" -> { if (i + 1 < args.length) blockIps.add(args[++i]); }
                case "--block-domain" -> { if (i + 1 < args.length) blockDomains.add(args[++i]); }
                case "--lbs" -> { if (i + 1 < args.length) lbs = Integer.parseInt(args[++i]); }
                case "--fps" -> { if (i + 1 < args.length) fps = Integer.parseInt(args[++i]); }
                case "--report-json" -> { if (i + 1 < args.length) reportJsonPath = args[++i]; }
                case "--report-csv" -> { if (i + 1 < args.length) reportCsvPath = args[++i]; }
                case "--simple" -> simple = true;
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

        long start = System.currentTimeMillis();
        TrafficReport report;
        if (simple) {
            DpiSimple engine = new DpiSimple(input, output, rules);
            engine.run();
            report = engine.getReport();
        } else {
            DpiEngine engine = new DpiEngine(input, output, rules, lbs, fps);
            engine.run();
            report = engine.getReport();
        }

        if (report != null) {
            report.setProcessingTimeMs(System.currentTimeMillis() - start);
            if (reportJsonPath != null) {
                ReportExporter.exportJson(report, Path.of(reportJsonPath));
            }
            if (reportCsvPath != null) {
                ReportExporter.exportCsv(report, Path.of(reportCsvPath));
            }
        }
    }
}


