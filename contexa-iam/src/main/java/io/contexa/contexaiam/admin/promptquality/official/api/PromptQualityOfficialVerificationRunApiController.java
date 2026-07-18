package io.contexa.contexaiam.admin.promptquality.official.api;

import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/verification")
public class PromptQualityOfficialVerificationRunApiController {

    private final PromptQualityRuntimeVerificationService verificationService;
    private final PromptQualityOfficialRunDetailService runDetailService;
    private final PromptQualityOfficialConsoleViewAssembler views;

    public PromptQualityOfficialVerificationRunApiController(
            PromptQualityRuntimeVerificationService verificationService,
            PromptQualityOfficialRunDetailService runDetailService,
            PromptQualityOfficialConsoleViewAssembler views) {
        this.verificationService = verificationService;
        this.runDetailService = runDetailService;
        this.views = views;
    }

    @PostMapping("/runtime-runs")
    public RuntimeEvidenceVerificationRun verifyRuntimeEvidence(
            @RequestParam(required = false) String packageId,
            @RequestBody(required = false) Map<String, Object> body,
            Authentication authentication) {
        String resolvedPackageId = views.firstText(packageId, views.stringValue(body, "packageId"));
        if (!StringUtils.hasText(resolvedPackageId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, views.message("promptQuality.official.run.packageIdRequired"));
        }
        String operator = authentication != null && StringUtils.hasText(authentication.getName())
                ? authentication.getName()
                : views.firstText(views.stringValue(body, "operatorId"), "oss-admin");
        return verificationService.verify(new RuntimeEvidenceVerificationRequest(
                resolvedPackageId,
                operator,
                Boolean.TRUE.equals(body == null ? null : body.get("forceReverification")),
                views.stringValue(body, "reverificationReason")));
    }

    @GetMapping("/runtime-runs")
    public List<OfficialRunPackageListItem> recentOfficialRuns(
            @RequestParam(defaultValue = "20") int limit) {
        return runDetailService.listRecentRunSummaries(limit);
    }

    @GetMapping("/runtime-runs/package/{packageId}")
    public OfficialRunPackageDetail packageOfficialRuns(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findPackageDetail(packageId, aggregateRunId);
    }

    @GetMapping("/runtime-runs/package/{packageId}/summary")
    public OfficialRunPackageSummary packageOfficialRunSummary(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findPackageSummary(packageId, aggregateRunId);
    }

    @PostMapping("/runtime-runs/package/{packageId}/reverify")
    public RuntimeEvidenceReverifyResult reverifyPackage(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId,
            @RequestBody(required = false) Map<String, Object> body,
            Authentication authentication) {
        String operator = authentication != null && StringUtils.hasText(authentication.getName())
                ? authentication.getName()
                : views.firstText(views.stringValue(body, "operatorId"), "oss-admin");
        String reason = views.firstText(
                views.stringValue(body, "reason"),
                views.stringValue(body, "reverificationReason"),
                "official verification recheck");
        return verificationService.reverify(new RuntimeEvidenceReverifyRequest(
                packageId,
                operator,
                reason,
                views.stringValue(body, "sourcePackageId"),
                views.firstText(aggregateRunId, views.stringValue(body, "sourceAggregateRunId")),
                views.stringList(body == null ? null : body.get("findingIds")),
                views.stringList(body == null ? null : body.get("issueIds"))));
    }

    @GetMapping("/runtime-runs/package/{packageId}/failure-details")
    public List<OfficialRunFailureCause> packageFailureDetails(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findFailureDetails(packageId, aggregateRunId);
    }

    @GetMapping("/runtime-runs/package/{packageId}/audit-payloads")
    public List<OfficialRunAuditSnapshot> packageAuditPayloads(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findAuditPayloads(packageId, aggregateRunId);
    }

    @GetMapping("/runtime-runs/package/{packageId}/execution-status")
    public OfficialVerificationExecutionStatus packageExecutionStatus(@PathVariable String packageId) {
        return verificationService.executionStatus(packageId);
    }

    @GetMapping("/runtime-runs/{runId}")
    public OfficialVerificationMetricTrace officialRunDetail(@PathVariable String runId) {
        return runDetailService.findRunDetail(runId);
    }

    @GetMapping("/runs/{runId}/metric-detail")
    public OfficialVerificationMetricTrace officialMetricTrace(@PathVariable String runId) {
        return runDetailService.findRunDetail(runId);
    }

    @GetMapping("/packages/{packageId}/prompt-comparison")
    public List<OfficialVerificationPromptComparison> packagePromptComparison(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findPackageDetail(packageId, aggregateRunId).promptComparisons();
    }

    @GetMapping("/packages/{packageId}/actual-prompt-problems")
    public List<OfficialActualPromptProblem> packageActualPromptProblems(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findActualPromptProblems(packageId, aggregateRunId);
    }
}