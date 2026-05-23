package dpi.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import dpi.model.TrafficReport;

import java.nio.file.Path;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AnalysisJob {
    public enum Status { PENDING, RUNNING, COMPLETED, FAILED }

    private final String id = UUID.randomUUID().toString();
    private volatile Status status = Status.PENDING;
    private volatile String errorMessage;

    @JsonIgnore private Path inputPath;
    @JsonIgnore private Path outputPath;
    @JsonIgnore private Path reportJsonPath;
    @JsonIgnore private Path reportCsvPath;

    private TrafficReport report;
    private volatile long startTime;
    private volatile long endTime;

    public String getId() { return id; }
    public Status getStatus() { return status; }
    public void setStatus(Status s) { this.status = s; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String m) { this.errorMessage = m; }
    public TrafficReport getReport() { return report; }
    public void setReport(TrafficReport r) { this.report = r; }
    public long getStartTime() { return startTime; }
    public void setStartTime(long t) { this.startTime = t; }
    public long getEndTime() { return endTime; }
    public void setEndTime(long t) { this.endTime = t; }

    @JsonProperty("outputPath") public String getOutputPathString() {
        return outputPath != null ? outputPath.toString() : null;
    }
    @JsonProperty("reportJsonPath") public String getReportJsonPathString() {
        return reportJsonPath != null ? reportJsonPath.toString() : null;
    }
    @JsonProperty("reportCsvPath") public String getReportCsvPathString() {
        return reportCsvPath != null ? reportCsvPath.toString() : null;
    }

    // package-private path accessors for service layer
    void setInputPath(Path p) { this.inputPath = p; }
    void setOutputPath(Path p) { this.outputPath = p; }
    void setReportJsonPath(Path p) { this.reportJsonPath = p; }
    void setReportCsvPath(Path p) { this.reportCsvPath = p; }
    Path getOutputPath() { return outputPath; }
    Path getReportCsvPath() { return reportCsvPath; }
}