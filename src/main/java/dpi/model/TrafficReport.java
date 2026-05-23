package dpi.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Structured traffic report suitable for JSON/CSV export and REST APIs.
 */
public class TrafficReport {
    private long totalPackets;
    private long totalBytes;
    private long tcpPackets;
    private long udpPackets;
    private long forwarded;
    private long dropped;
    private long processingTimeMs;
    private List<AppBreakdown> appBreakdown = new ArrayList<>();
    private List<SniEntry> detectedSnis = new ArrayList<>();

    public long getTotalPackets() { return totalPackets; }
    public void setTotalPackets(long v) { this.totalPackets = v; }

    public long getTotalBytes() { return totalBytes; }
    public void setTotalBytes(long v) { this.totalBytes = v; }

    public long getTcpPackets() { return tcpPackets; }
    public void setTcpPackets(long v) { this.tcpPackets = v; }

    public long getUdpPackets() { return udpPackets; }
    public void setUdpPackets(long v) { this.udpPackets = v; }

    public long getForwarded() { return forwarded; }
    public void setForwarded(long v) { this.forwarded = v; }

    public long getDropped() { return dropped; }
    public void setDropped(long v) { this.dropped = v; }

    public long getProcessingTimeMs() { return processingTimeMs; }
    public void setProcessingTimeMs(long v) { this.processingTimeMs = v; }

    public List<AppBreakdown> getAppBreakdown() { return appBreakdown; }
    public void setAppBreakdown(List<AppBreakdown> v) { this.appBreakdown = v; }

    public List<SniEntry> getDetectedSnis() { return detectedSnis; }
    public void setDetectedSnis(List<SniEntry> v) { this.detectedSnis = v; }

    public static class AppBreakdown {
        private String appType;
        private long count;
        private double percentage;
        private boolean blocked;
        private String bar;

        public String getAppType() { return appType; }
        public void setAppType(String v) { this.appType = v; }

        public long getCount() { return count; }
        public void setCount(long v) { this.count = v; }

        public double getPercentage() { return percentage; }
        public void setPercentage(double v) { this.percentage = v; }

        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean v) { this.blocked = v; }

        public String getBar() { return bar; }
        public void setBar(String v) { this.bar = v; }
    }

    public static class SniEntry {
        private String sni;
        private String appType;

        public String getSni() { return sni; }
        public void setSni(String v) { this.sni = v; }

        public String getAppType() { return appType; }
        public void setAppType(String v) { this.appType = v; }
    }
}
