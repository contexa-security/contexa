package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRequest;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionCheckResponse;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionMetricResponse;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialInspectionRunResponse;
import org.springframework.util.StringUtils;

import java.util.Comparator;
import java.util.List;

public class DefaultOfficialPromptQualityInspectionService implements OfficialPromptQualityInspectionService {

    private final OfficialSealedEvidenceVerificationRuntime runtime;

    public DefaultOfficialPromptQualityInspectionService(OfficialSealedEvidenceVerificationRuntime runtime) {
        this.runtime = runtime;
    }

    @Override
    public OfficialInspectionRunResponse execute(String packageId, String operatorId) {
        if (!StringUtils.hasText(packageId)) {
            throw new IllegalArgumentException("packageId is required.");
        }
        return toResponse(runtime.executeAll(new OfficialSealedEvidenceVerificationRequest(
                packageId.trim(),
                StringUtils.hasText(operatorId) ? operatorId.trim() : "oss-official-inspection")));
    }

    @Override
    public OfficialInspectionRunResponse findLatest(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            throw new IllegalArgumentException("packageId is required.");
        }
        return toResponse(runtime.findByPackageId(packageId.trim()));
    }

    private OfficialInspectionRunResponse toResponse(OfficialSealedEvidenceVerificationResult result) {
        List<OfficialInspectionMetricResponse> metrics = result.runs() == null
                ? List.of()
                : result.runs().stream()
                .sorted(Comparator.comparing(OfficialVerificationRunView::endpointKey))
                .map(this::toMetric)
                .toList();
        int passedMetrics = (int) metrics.stream()
                .filter(metric -> "success".equalsIgnoreCase(metric.state()))
                .count();
        return new OfficialInspectionRunResponse(
                result.aggregateRunId(),
                result.packageId(),
                result.operatorId(),
                result.generatedAt(),
                result.integrityValid(),
                passedMetrics,
                metrics.size(),
                metrics);
    }

    private OfficialInspectionMetricResponse toMetric(OfficialVerificationRunView run) {
        List<OfficialInspectionCheckResponse> checks = run.checks() == null
                ? List.of()
                : run.checks().stream()
                .map(this::toCheck)
                .toList();
        return new OfficialInspectionMetricResponse(
                run.endpointKey(),
                run.endpointLabel(),
                run.state(),
                run.score(),
                run.passedChecks(),
                run.totalChecks(),
                run.message(),
                checks);
    }

    private OfficialInspectionCheckResponse toCheck(OfficialVerificationCheckResultView check) {
        return new OfficialInspectionCheckResponse(
                check.checkCode(),
                check.label(),
                check.pass(),
                check.expectedValue(),
                check.actualValue(),
                check.severity(),
                check.failureType(),
                check.source());
    }
}
