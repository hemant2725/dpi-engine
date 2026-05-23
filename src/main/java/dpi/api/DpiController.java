package dpi.api;

import dpi.model.TrafficReport;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class DpiController {
    private final AnalysisService service;

    public DpiController(AnalysisService service) {
        this.service = service;
    }

    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AnalysisJob> analyze(
            @RequestParam("pcap") MultipartFile pcap,
            @RequestParam(value = "blockApp", required = false) List<String> blockApps,
            @RequestParam(value = "blockIp", required = false) List<String> blockIps,
            @RequestParam(value = "blockDomain", required = false) List<String> blockDomains,
            @RequestParam(value = "simple", required = false, defaultValue = "false") boolean simple,
            @RequestParam(value = "lbs", required = false, defaultValue = "2") int lbs,
            @RequestParam(value = "fps", required = false, defaultValue = "2") int fps) throws IOException {

        AnalysisJob job = service.submit(pcap, blockApps, blockIps, blockDomains, simple, lbs, fps);
        return ResponseEntity.accepted().body(job);
    }

    @GetMapping("/jobs/{id}")
    public ResponseEntity<AnalysisJob> getJob(@PathVariable String id) {
        AnalysisJob job = service.get(id);
        return job != null ? ResponseEntity.ok(job) : ResponseEntity.notFound().build();
    }

    @GetMapping("/jobs/{id}/report")
    public ResponseEntity<TrafficReport> getReport(@PathVariable String id) {
        AnalysisJob job = service.get(id);
        if (job == null || job.getReport() == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(job.getReport());
    }

    @GetMapping("/jobs/{id}/output")
    public ResponseEntity<Resource> downloadOutput(@PathVariable String id) {
        AnalysisJob job = service.get(id);
        if (job == null || job.getOutputPath() == null) return ResponseEntity.notFound().build();
        FileSystemResource res = new FileSystemResource(job.getOutputPath());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"output.pcap\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(res);
    }

    @GetMapping("/jobs/{id}/report.csv")
    public ResponseEntity<Resource> downloadCsv(@PathVariable String id) {
        AnalysisJob job = service.get(id);
        if (job == null || job.getReportCsvPath() == null) return ResponseEntity.notFound().build();
        FileSystemResource res = new FileSystemResource(job.getReportCsvPath());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"report.csv\"")
                .contentType(MediaType.TEXT_PLAIN)
                .body(res);
    }
}
