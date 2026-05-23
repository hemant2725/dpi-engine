package dpi.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dpi.model.TrafficReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Exports {@link TrafficReport} to JSON or CSV.
 */
public class ReportExporter {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void exportJson(TrafficReport report, Path path) throws IOException {
        MAPPER.writeValue(path.toFile(), report);
    }

    public static void exportCsv(TrafficReport report, Path path) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Metric,Value\n");
        sb.append("Total Packets,").append(report.getTotalPackets()).append('\n');
        sb.append("Total Bytes,").append(report.getTotalBytes()).append('\n');
        sb.append("TCP Packets,").append(report.getTcpPackets()).append('\n');
        sb.append("UDP Packets,").append(report.getUdpPackets()).append('\n');
        sb.append("Forwarded,").append(report.getForwarded()).append('\n');
        sb.append("Dropped,").append(report.getDropped()).append('\n');
        sb.append("Processing Time (ms),").append(report.getProcessingTimeMs()).append('\n');

        sb.append("\nApplication,Count,Percentage,Blocked\n");
        for (var app : report.getAppBreakdown()) {
            sb.append(app.getAppType()).append(',')
              .append(app.getCount()).append(',')
              .append(app.getPercentage()).append(',')
              .append(app.isBlocked()).append('\n');
        }

        sb.append("\nSNI,Application\n");
        for (var sni : report.getDetectedSnis()) {
            sb.append(sni.getSni()).append(',')
              .append(sni.getAppType()).append('\n');
        }

        Files.writeString(path, sb.toString());
    }
}