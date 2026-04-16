package io.contexa.site.controller;

import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkManifest;
import io.contexa.contexacoreenterprise.benchmark.publication.PublishedBenchmarkSummary;
import io.contexa.site.service.PublicBenchmarkFacade;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@Controller
public class PublicBenchmarkController {

    private final PublicBenchmarkFacade benchmarkFacade;

    public PublicBenchmarkController(PublicBenchmarkFacade benchmarkFacade) {
        this.benchmarkFacade = benchmarkFacade;
    }

    @GetMapping("/benchmark")
    public String benchmarkOverview(Model model) {
        return benchmarkFacade.overview(model);
    }

    @GetMapping("/benchmark/human")
    public String benchmarkHuman(Model model) {
        return renderFamily("human", model);
    }

    @GetMapping("/benchmark/agent")
    public String benchmarkAgent(Model model) {
        return renderFamily("agent", model);
    }

    @GetMapping("/benchmark/protocol")
    public String benchmarkProtocol(Model model) {
        return renderFamily("protocol", model);
    }

    @GetMapping("/benchmark/verification")
    public String benchmarkVerification(Model model) {
        return renderFamily("verification", model);
    }

    @GetMapping("/benchmark/soar")
    public String benchmarkSoar(Model model) {
        return renderFamily("soar", model);
    }

    @GetMapping("/benchmark/java")
    public String benchmarkJava(Model model) {
        return renderFamily("java", model);
    }

    @GetMapping("/benchmark/methodology")
    public String benchmarkMethodology(Model model) {
        return benchmarkFacade.methodology(model);
    }

    @GetMapping("/benchmark/trends")
    public String benchmarkTrends(Model model) {
        return benchmarkFacade.trends(model);
    }

    @GetMapping("/benchmark/family/{family}")
    public String benchmarkFamily(@PathVariable String family, Model model) {
        return renderFamily(family, model);
    }

    @GetMapping("/benchmark/leaderboard")
    public String benchmarkLeaderboard(Model model) {
        return benchmarkFacade.leaderboard(model);
    }

    @GetMapping("/benchmark/self-run")
    public String benchmarkSelfRun(Model model) {
        return benchmarkFacade.selfRun(model);
    }

    @GetMapping("/benchmark/certification")
    public String benchmarkCertification(Model model) {
        return benchmarkFacade.certification(model);
    }

    @GetMapping("/benchmark/reports/{slug}")
    public String benchmarkReportCanonical(@PathVariable String slug, Model model) {
        return renderBenchmarkReport(slug, model);
    }

    @GetMapping("/benchmark/{slug}")
    public String benchmarkReportLegacy(@PathVariable String slug, Model model) {
        return renderBenchmarkReport(slug, model);
    }

    @GetMapping(value = "/benchmark/reports/{slug}/summary.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PublishedBenchmarkSummary> benchmarkReportSummary(@PathVariable String slug) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.inline().filename(slug + "-summary.json").build().toString())
                    .body(benchmarkFacade.summary(slug));
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    @GetMapping(value = "/benchmark/reports/{slug}/chart-data.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> benchmarkReportChartData(@PathVariable String slug) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.inline().filename(slug + "-chart-data.json").build().toString())
                    .body(benchmarkFacade.chartData(slug));
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    @GetMapping(value = "/benchmark/reports/{slug}/manifest.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PublishedBenchmarkManifest> benchmarkReportManifest(@PathVariable String slug) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.inline().filename(slug + "-manifest.json").build().toString())
                    .body(benchmarkFacade.manifest(slug));
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    @GetMapping(value = "/benchmark/reports/{slug}/html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> benchmarkReportHtml(@PathVariable String slug) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.inline().filename(slug + "-benchmark-report.html").build().toString())
                    .body(benchmarkFacade.reportHtml(slug));
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    @GetMapping(value = "/benchmark/reports/{slug}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> benchmarkReportPdf(@PathVariable String slug) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(slug + "-benchmark-report.pdf").build().toString())
                    .body(benchmarkFacade.reportPdf(slug));
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    private String renderBenchmarkReport(String slug, Model model) {
        try {
            return benchmarkFacade.detail(slug, model);
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }

    private String renderFamily(String family, Model model) {
        try {
            return benchmarkFacade.family(family, model);
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, exception.getMessage(), exception);
        }
    }
}