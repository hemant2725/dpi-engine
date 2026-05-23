package dpi.api;

import dpi.DpiEngine;
import dpi.DpiSimple;
import dpi.engine.ReportExporter;
import dpi.engine.RuleManager;
import dpi.model.AppType;
import dpi.model.TrafficReport;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

@Service
public class AnalysisService {
    private final Map<String, AnalysisJob> jobs = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final Path workDir;

    public AnalysisService() throws IOException {
        this.workDir = Files.createTempDirectory("dpi-jobs");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            executor.shutdown();
            try { executor.awaitTermination(30, TimeUnit.SECONDS); }
            catch (InterruptedException e) { executor.shutdownNow(); }
        }));
    }

    public AnalysisJob submit(MultipartFile file,
                              List<String> blockApps,
                              List<String> blockIps,
                              List<String> blockDomains,
                              boolean simple,
                              int lbs, int fps) throws IOException {
        AnalysisJob job = new AnalysisJob();
        job.setStatus(AnalysisJob.Status.PENDING);
        job.setStartTime(System.currentTimeMillis());

        Path jobDir = workDir.resolve(job.getId());
        Files.createDirectories(jobDir);

        Path input = jobDir.resolve("input.pcap");
        Path output = jobDir.resolve("output.pcap");
        Path reportJson = jobDir.resolve("report.json");
        Path reportCsv = jobDir.resolve("report.csv");

        file.transferTo(input);
        job.setInputPath(input);
        job.setOutputPath(output);
        job.setReportJsonPath(reportJson);
        job.setReportCsvPath(reportCsv);
        jobs.put(job.getId(), job);

        executor.submit(() -> {
            try {
                job.setStatus(AnalysisJob.Status.RUNNING);
                RuleManager rules = new RuleManager(blockDomains);
                if (blockIps != null) blockIps.forEach(rules::blockIp);
                if (blockApps != null) {
                    blockApps.forEach(a -> {
                        try { rules.blockApp(AppType.valueOf(a.toUpperCase())); }
                        catch (IllegalArgumentException ignored) {}
                    });
                }

                TrafficReport report;
                if (simple) {
                    DpiSimple engine = new DpiSimple(input.toString(), output.toString(), rules);
                    engine.run();
                    report = engine.getReport();
                } else {
                    DpiEngine engine = new DpiEngine(input.toString(), output.toString(), rules, lbs, fps);
                    engine.run();
                    report = engine.getReport();
                }

                report.setProcessingTimeMs(System.currentTimeMillis() - job.getStartTime());
                job.setReport(report);
                ReportExporter.exportJson(report, reportJson);
                ReportExporter.exportCsv(report, reportCsv);
                job.setStatus(AnalysisJob.Status.COMPLETED);
            } catch (Exception e) {
                job.setStatus(AnalysisJob.Status.FAILED);
                job.setErrorMessage(e.getMessage());
            } finally {
                job.setEndTime(System.currentTimeMillis());
            }
        });

        return job;
    }

    public AnalysisJob get(String id) { return jobs.get(id); }
}