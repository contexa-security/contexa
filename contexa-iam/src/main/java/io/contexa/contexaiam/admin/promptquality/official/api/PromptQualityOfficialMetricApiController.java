package io.contexa.contexaiam.admin.promptquality.official.api;

import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/verification/runtime-runs/package")
public class PromptQualityOfficialMetricApiController {

    private final PromptQualityOfficialRunDetailService runDetailService;
    private final PromptQualityOfficialConsoleViewAssembler views;

    public PromptQualityOfficialMetricApiController(
            PromptQualityOfficialRunDetailService runDetailService,
            PromptQualityOfficialConsoleViewAssembler views) {
        this.runDetailService = runDetailService;
        this.views = views;
    }

    @GetMapping("/{packageId}/metric-families")
    public Map<String, Object> packageMetricFamilies(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        OfficialRunPackageDetail detail = runDetailService.findPackageDetail(packageId, aggregateRunId);
        OfficialRunPackageSummary summary = runDetailService.findPackageSummary(packageId, aggregateRunId);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("prompt", views.metricFamilyPayload(detail, "prompt"));
        payload.put("decision", views.metricFamilyPayload(detail, "decision"));
        payload.put("other", views.metricFamilyPayload(detail, "other"));
        payload.put("finalDecision", summary.finalDecision());
        payload.put("blocked", summary.blocked());
        payload.put("blockReasonSummary", summary.blockReasonSummary());
        return payload;
    }

    @GetMapping("/{packageId}/metrics/prompt")
    public Map<String, Object> packagePromptMetrics(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return views.metricFamilyPayload(
                runDetailService.findPackageDetail(packageId, aggregateRunId), "prompt");
    }

    @GetMapping("/{packageId}/metrics/llm-decision")
    public Map<String, Object> packageLlmDecisionMetrics(@PathVariable String packageId) {
        throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                views.message("promptQuality.official.metric.enterpriseOnly"));
    }

    @GetMapping("/{packageId}/metrics/{metricCode}/failure-details")
    public List<OfficialRunFailureCause> packageMetricFailureDetails(
            @PathVariable String packageId,
            @PathVariable String metricCode,
            @RequestParam(required = false) String aggregateRunId) {
        String normalizedMetric = views.normalizeMetricCode(metricCode);
        return runDetailService.findFailureDetails(packageId, aggregateRunId).stream()
                .filter(failure -> views.normalizeMetricCode(failure.metricCode()).equals(normalizedMetric))
                .toList();
    }

    @GetMapping("/{packageId}/evidence-package")
    public RuntimeEvidencePackageDetail packageEvidencePackage(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return runDetailService.findPackageDetail(packageId, aggregateRunId).sealedEvidence();
    }

    @GetMapping("/{packageId}/reverify-options")
    public Map<String, Object> packageReverifyOptions(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return views.reverifyOptionsPayload(
                runDetailService.findPackageDetail(packageId, aggregateRunId));
    }
}