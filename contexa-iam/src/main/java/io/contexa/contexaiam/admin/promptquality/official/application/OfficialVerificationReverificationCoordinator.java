package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;

public final class OfficialVerificationReverificationCoordinator {

    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialVerificationProgressRecorder progressRecorder;
    private final PromptQualityMessageResolver messageResolver;

    public OfficialVerificationReverificationCoordinator(
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationProgressRecorder progressRecorder,
            PromptQualityMessageResolver messageResolver) {
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.progressRecorder = Objects.requireNonNull(progressRecorder, "progressRecorder");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public RuntimeEvidenceVerificationRequest verificationRequest(RuntimeEvidenceReverifyRequest request) {
        String operatorId = firstNonBlank(request == null ? null : request.operatorId(), "runtime-pqa");
        return new RuntimeEvidenceVerificationRequest(
                request == null ? null : request.packageId(),
                operatorId,
                true,
                firstNonBlank(
                        request == null ? null : request.reason(),
                        "Reverification requested after remediation."));
    }

    public RuntimeEvidenceReverifyResult complete(
            RuntimeEvidenceReverifyRequest request,
            RuntimeEvidenceVerificationRun run) {
        String operatorId = firstNonBlank(request == null ? null : request.operatorId(), "runtime-pqa");
        List<RuntimeEvidenceReverifyFindingResult> findingResults = request == null
                ? List.of()
                : operatorSnapshotService.recordReverificationResults(
                        request.sourcePackageId(),
                        request.sourceAggregateRunId(),
                        request.findingIds(),
                        request.issueIds(),
                        run,
                        operatorId);
        boolean linkedCriteriaSatisfied = !findingResults.isEmpty()
                && findingResults.stream().allMatch(RuntimeEvidenceReverifyFindingResult::resolved);
        PromptQualityProcessScope scope = new PromptQualityProcessScope(
                firstNonBlank(run.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                run.resourceUrl(),
                run.resourceId(),
                run.httpMethod(),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
        progressRecorder.recordReverification(
                scope, run, findingResults, linkedCriteriaSatisfied, operatorId);
        return new RuntimeEvidenceReverifyResult(
                run.packageId(),
                run,
                instruction(run, findingResults, linkedCriteriaSatisfied),
                request == null ? null : request.sourcePackageId(),
                request == null ? null : request.sourceAggregateRunId(),
                linkedCriteriaSatisfied,
                findingResults);
    }

    private String instruction(
            RuntimeEvidenceVerificationRun run,
            List<RuntimeEvidenceReverifyFindingResult> findingResults,
            boolean linkedCriteriaSatisfied) {
        if (findingResults != null && !findingResults.isEmpty()) {
            long unresolved = findingResults.stream().filter(result -> !result.resolved()).count();
            if (linkedCriteriaSatisfied && run.officialVerificationPassed()) {
                return message("enterprise.pqa.runtimeVerification.reverify.linkedPassed");
            }
            if (unresolved > 0) {
                return message(
                        "enterprise.pqa.runtimeVerification.reverify.unresolvedTpl",
                        unresolved);
            }
            return message("enterprise.pqa.runtimeVerification.reverify.criteriaPassedVerdictIneligible");
        }
        return run.officialVerificationPassed()
                ? message("enterprise.pqa.runtimeVerification.reverify.passed")
                : message("enterprise.pqa.runtimeVerification.reverify.blocked");
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}