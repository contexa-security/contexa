package io.contexa.demo.experience.report.controller;

import io.contexa.demo.experience.report.dto.ReportCommand;
import io.contexa.demo.experience.report.dto.ReportSummary;
import io.contexa.demo.experience.report.dto.StoredReport;
import io.contexa.demo.experience.report.render.ReportRenderer;
import io.contexa.demo.experience.report.service.ReportService;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab")
public class ReportController extends AbstractVisitorController {

    private final ReportService reports;
    private final ReportRenderer renderer;
    private final DocumentCodec documents;

    public ReportController(ReportService reports, ReportRenderer renderer, DocumentCodec documents) {
        this.reports = reports;
        this.renderer = renderer;
        this.documents = documents;
    }

    @PostMapping("/runs/{runId}/reports")
    public ResponseEntity<StoredReport> capture(@PathVariable UUID runId, @Valid @RequestBody ReportCommand command,
            HttpServletRequest request) {
        return result(reports.capture(visitorId(request), runId, command));
    }

    @GetMapping("/runs/{runId}/reports")
    public ResponseEntity<List<ReportSummary>> list(@PathVariable UUID runId, HttpServletRequest request) {
        return result(reports.list(visitorId(request), runId));
    }

    @GetMapping("/reports/{reportId}")
    public ResponseEntity<StoredReport> find(@PathVariable UUID reportId, HttpServletRequest request) {
        return result(reports.find(visitorId(request), reportId));
    }

    @GetMapping("/reports/{reportId}/export")
    public ResponseEntity<String> export(@PathVariable UUID reportId,
            @RequestParam(defaultValue = "json") String format,
            @RequestParam(defaultValue = "ko") String language, HttpServletRequest request) {
        if (!Set.of("json", "html").contains(format) || !Set.of("ko", "en").contains(language)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "UNSUPPORTED_REPORT_FORMAT");
        }
        var report = reports.find(visitorId(request), reportId);
        String body = "html".equals(format) ? renderer.html(report, language) : documents.write(report);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"contexa-report-" + reportId + "." + format + "\"")
                .header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.parseMediaType("html".equals(format)
                        ? "text/html;charset=UTF-8" : "application/json;charset=UTF-8"))
                .body(body);
    }
}
