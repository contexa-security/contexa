package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The inspection console API: the overview and the sealed packages of a capture period (the last seven days unless
 * given), a package's inspection detail, and the operator's re-inspection of a package or a period.
 */
@RestController
@RequestMapping("/contexa/admin/api/prompt-inspection")
@PreAuthorize("hasRole('ADMIN')")
public class PromptInspectionApiController {


    private final JdbcPromptInspectionQueries queries;
    private final PromptInspectionConsole console;
    private final PromptInspectionReinspection reinspection;
    private final Clock clock;

    public PromptInspectionApiController(JdbcPromptInspectionQueries queries, PromptInspectionConsole console,
                                         PromptInspectionReinspection reinspection, Clock clock) {
        this.queries = Objects.requireNonNull(queries, "queries");
        this.console = Objects.requireNonNull(console, "console");
        this.reinspection = Objects.requireNonNull(reinspection, "reinspection");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** A capture period to inspect again, both ends included. */
    public record PeriodRequest(Instant from, Instant to) {
    }

    @GetMapping("/overview")
    public JdbcPromptInspectionQueries.Overview overview(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        Instant end = to != null ? to : clock.instant();
        return queries.overview(from != null ? from : end.minus(PromptInspectionScreen.DEFAULT_PERIOD), end);
    }

    @GetMapping("/packages")
    public JdbcPromptInspectionQueries.PackagePage packages(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) String verdict,
            @RequestParam(required = false) String checkCode,
            @RequestParam(required = false) String block,
            @RequestParam(required = false) String entry,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = PromptInspectionScreen.DEFAULT_PAGE_SIZE) int size) {
        Instant end = to != null ? to : clock.instant();
        return queries.packages(new JdbcPromptInspectionQueries.PackageFilter(
                from != null ? from : end.minus(PromptInspectionScreen.DEFAULT_PERIOD), end, verdict, checkCode, block, entry), page, size);
    }

    @GetMapping("/packages/{packageId}")
    public ResponseEntity<PromptInspectionConsole.Detail> detail(@PathVariable String packageId) {
        return console.detail(packageId).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/packages/{packageId}/reinspect")
    public ResponseEntity<Map<String, Object>> reinspect(@PathVariable String packageId) {
        return reinspection.reinspect(packageId).map(PromptInspectionApiController::summary).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/reinspections")
    public PromptInspectionReinspection.PeriodStatus requestReinspection(@RequestBody PeriodRequest request) {
        if (request == null || request.from() == null || request.to() == null || request.to().isBefore(request.from())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A period from and to is required");
        }
        return reinspection.request(request.from(), request.to());
    }

    /** How far the automatic round has come with a period it was asked to inspect again. */
    @GetMapping("/reinspections")
    public PromptInspectionReinspection.PeriodStatus reinspectionStatus(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        if (to.isBefore(from)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A period from and to is required");
        }
        return reinspection.status(from, to);
    }

    private static Map<String, Object> summary(PromptInspectionResult result) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("packageId", result.packageId());
        summary.put("verdict", result.verdict().name());
        summary.put("inspectorVersion", result.inspectorVersion());
        summary.put("mismatchCount", result.mismatchCount());
        summary.put("unverifiableCount", result.unverifiableCount());
        return summary;
    }
}
