package dpi.engine;

import dpi.model.AppType;
import dpi.model.TrafficReport;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds a {@link TrafficReport} from raw counters.
 */
public class ReportBuilder {
    public static TrafficReport build(
            long totalPackets, long totalBytes, long tcp, long udp,
            long forwarded, long dropped,
            Map<AppType, Long> appCounts, Set<String> detectedSnis,
            RuleManager ruleManager) {

        TrafficReport r = new TrafficReport();
        r.setTotalPackets(totalPackets);
        r.setTotalBytes(totalBytes);
        r.setTcpPackets(tcp);
        r.setUdpPackets(udp);
        r.setForwarded(forwarded);
        r.setDropped(dropped);

        List<TrafficReport.AppBreakdown> breakdown = new ArrayList<>();
        var sorted = appCounts.entrySet().stream()
                .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
                .toList();

        for (var e : sorted) {
            AppType app = e.getKey();
            long count = e.getValue();
            double pct = totalPackets > 0 ? (count * 100.0 / totalPackets) : 0.0;
            boolean blocked = ruleManager.isAppBlocked(app);
            int hashes = Math.min(20, (int) Math.round(pct / 5.0));

            TrafficReport.AppBreakdown ab = new TrafficReport.AppBreakdown();
            ab.setAppType(app.toString());
            ab.setCount(count);
            ab.setPercentage(Math.round(pct * 10.0) / 10.0);
            ab.setBlocked(blocked);
            ab.setBar("#".repeat(hashes));
            breakdown.add(ab);
        }
        r.setAppBreakdown(breakdown);

        List<TrafficReport.SniEntry> snis = new ArrayList<>();
        for (String s : detectedSnis) {
            String[] parts = s.split(" -> ", 2);
            TrafficReport.SniEntry entry = new TrafficReport.SniEntry();
            entry.setSni(parts[0]);
            entry.setAppType(parts.length > 1 ? parts[1] : AppType.UNKNOWN.toString());
            snis.add(entry);
        }
        r.setDetectedSnis(snis);
        return r;
    }
}
