package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.state.PromptQualityStateDimension;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Owns process progress and audit recording for official runtime verification.
 */
public final class OfficialVerificationProgressRecorder {

    private final PromptQualityProcessRunService processRunService;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialVerificationExecutionLockService executionLockService;
    private final PromptQualityMessageResolver messageResolver;

    public OfficialVerificationProgressRecorder(
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationExecutionLockService executionLockService,
            PromptQualityMessageResolver messageResolver) {
        this.processRunService = Objects.requireNonNull(processRunService, "processRunService");
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.executionLockService = Objects.requireNonNull(executionLockService, "executionLockService");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public void completePrerequisites(
            PromptQualityProcessScope scope,
            SealedEvidencePackage evidencePackage,
            boolean integrityValid,
            RuntimeEvidencePromptConsistencyResult promptConsistency,
            String operatorId) {
        List<PromptQualityProcessStepSnapshot> steps = processRunService.steps(scope);
        if (shouldComplete(steps, PromptQualityProcessCodes.PROTECTABLE_RESOURCES)) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("packageId", evidencePackage.getPackageId());
            result.put("resourceId", scope.resourceId());
            result.put("resourceUrl", scope.resourceUrl());
            result.put("httpMethod", scope.httpMethod());
            processRunService.completeStep(
                    scope,
                    PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL.name(),
                    "PENDING_VERIFICATION",
                    scope.resourceId(),
                    PromptQualityVerificationRoutes.resourceDetail(scope),
                    message("enterprise.pqa.runtimeVerification.process.resourceResolved"),
                    message("enterprise.pqa.runtimeVerification.process.resourceNextAction"),
                    result,
                    operatorId,
                    message("enterprise.pqa.runtimeVerification.process.resourcePrerequisiteCompleted"));
        }
        if (shouldComplete(steps, PromptQualityProcessCodes.RUNTIME_EVIDENCE)) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("packageId", evidencePackage.getPackageId());
            result.put("sealed", evidencePackage.isSealed());
            result.put("integrityValid", integrityValid);
            result.put("promptConsistencyState", promptConsistency == null ? null : promptConsistency.state());
            processRunService.completeStep(
                    scope,
                    PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                    PromptQualityStateDimension.RUNTIME_EVIDENCE.name(),
                    runtimeEvidenceState(evidencePackage, integrityValid, promptConsistency),
                    evidencePackage.getPackageId(),
                    PromptQualityVerificationRoutes.runtimeEvidence(evidencePackage.getPackageId(), scope),
                    message("enterprise.pqa.runtimeVerification.process.evidenceResolved"),
                    message("enterprise.pqa.runtimeVerification.process.evidenceNextAction"),
                    result,
                    operatorId,
                    message("enterprise.pqa.runtimeVerification.process.evidencePrerequisiteCompleted"));
        }
    }

    public void assertProcessReady(PromptQualityProcessScope scope) {
        List<String> previous = new ArrayList<>();
        for (var step : processRunService.steps(scope)) {
            if (PromptQualityProcessCodes.OFFICIAL_VERIFICATION.equals(step.stepCode())) {
                String state = normalized(step.executionState());
                if (PromptQualityProcessCodes.RUNNING.equals(state)
                        || PromptQualityProcessCodes.COMPLETED.equals(state)
                        || PromptQualityProcessCodes.FAILED.equals(state)) {
                    return;
                }
                break;
            }
            if (!PromptQualityProcessCodes.COMPLETED.equalsIgnoreCase(step.executionState())) {
                previous.add(step.stepCode());
            }
        }
        if (!previous.isEmpty()) {
            throw new IllegalStateException(message(
                    "enterprise.pqa.runtimeVerification.error.processSequenceBlocked",
                    previous.get(0)));
        }
    }

    public void start(PromptQualityProcessScope scope, SealedEvidencePackage evidencePackage, String operatorId) {
        processRunService.startStep(
                scope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                evidencePackage.getPackageId(),
                PromptQualityVerificationRoutes.readiness(evidencePackage.getPackageId(), scope, null),
                operatorId,
                message("enterprise.pqa.runtimeVerification.process.officialStarted"));
    }

    public void recordMetricFinished(
            OfficialVerificationExecutionLockService.ExecutionRecord executionRecord,
            String aggregateRunId,
            List<? extends OfficialVerificationRunView> runs) {
        if (executionRecord == null || runs == null || runs.isEmpty()) {
            return;
        }
        int total = Math.max(runs.size(), 1);
        for (int index = 0; index < runs.size(); index++) {
            OfficialVerificationRunView run = runs.get(index);
            executionLockService.markMetricCompleted(
                    executionRecord,
                    aggregateRunId,
                    run == null ? null : run.endpointKey(),
                    OfficialVerificationProgressPolicy.metricProgress(index + 1, total));
        }
    }

    public void recordCompletion(
            PromptQualityProcessScope scope,
            OfficialVerificationVerdict verdict,
            SealedEvidencePackage evidencePackage,
            String aggregateRunId,
            int failedMetricCount,
            List<String> nextActions) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("aggregateRunId", aggregateRunId);
        result.put("officialVerdict", verdict);
        result.put("failedMetricCount", failedMetricCount);
        result.put("eligible", verdict.eligible());
        processRunService.completeStep(
                scope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                verdict.status().name(),
                aggregateRunId,
                PromptQualityVerificationRoutes.readiness(evidencePackage.getPackageId(), scope, aggregateRunId),
                verdict.eligible()
                        ? message("enterprise.pqa.runtimeVerification.process.eligibleSummary")
                        : message("enterprise.pqa.runtimeVerification.process.ineligibleSummary"),
                first(nextActions),
                result,
                "runtime-pqa",
                message("enterprise.pqa.runtimeVerification.process.completed"));
        if (!verdict.eligible()) {
            processRunService.startStep(
                    scope,
                    PromptQualityProcessCodes.REMEDIATION,
                    PromptQualityStateDimension.PROCESS_STAGE.name(),
                    verdict.status().name(),
                    aggregateRunId,
                    PromptQualityVerificationRoutes.metrics(evidencePackage.getPackageId(), scope, aggregateRunId),
                    "runtime-pqa",
                    message("enterprise.pqa.runtimeVerification.process.blockingFindings"));
        }
    }

    public void recordAuditSnapshot(AuditSnapshotCommand command) {
        Map<String, Object> payload = auditPayload(command);
        operatorSnapshotService.recordAuditSnapshot(
                command.evidencePackage().getTenantId(),
                command.aggregateRunId(),
                command.evidencePackage().getPackageId(),
                null,
                command.assuranceCase() == null ? null : command.assuranceCase().caseId(),
                command.verdict().status().name(),
                command.verdict().status().name(),
                size(command.metrics()),
                command.failedMetricCount(),
                false,
                command.promptHash(),
                command.contextHash(),
                immutable(command.findings()),
                immutable(command.nextActions()),
                payload,
                firstNonBlank(command.operatorId(), "runtime-pqa"));
        processRunService.recordEvent(
                command.scope(),
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                "OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT",
                payload,
                firstNonBlank(command.operatorId(), "runtime-pqa"),
                message("enterprise.pqa.runtimeVerification.process.auditSnapshotPersisted"));
    }

    private Map<String, Object> auditPayload(AuditSnapshotCommand command) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", command.evidencePackage().getPackageId());
        payload.put("aggregateRunId", command.aggregateRunId());
        payload.put("requestId", command.requestId());
        payload.put("tenantId", command.evidencePackage().getTenantId());
        payload.put("userId", command.evidencePackage().getUserId());
        payload.put("resourceUrl", command.scope().resourceUrl());
        payload.put("resourceId", command.scope().resourceId());
        payload.put("httpMethod", command.scope().httpMethod());
        payload.put("officialVerdict", command.verdict());
        payload.put("caseId", command.assuranceCase() == null ? null : command.assuranceCase().caseId());
        payload.put("totalMetricCount", size(command.metrics()));
        payload.put("failedMetricCount", command.failedMetricCount());
        payload.put("failedMetricCodes", immutable(command.failedMetricCodes()));
        payload.put("promptHash", command.promptHash());
        payload.put("contextHash", command.contextHash());
        payload.put("promptGovernanceVersion", command.promptGovernanceVersion());
        payload.put("metricSetVersion", command.metricSetVersion());
        payload.put("officialVerificationEngineVersion", command.engineVersion());
        payload.put("blockingFindings", immutable(command.findings()));
        payload.put("nextActions", immutable(command.nextActions()));
        return payload;
    }
    public void recordIneligibleBeforeMetrics(
            PromptQualityProcessScope scope,
            SealedEvidencePackage evidencePackage,
            String aggregateRunId,
            OfficialVerificationVerdict verdict,
            List<String> nextActions,
            String operatorId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", evidencePackage.getPackageId());
        payload.put("aggregateRunId", aggregateRunId);
        payload.put("officialVerdict", verdict);
        payload.put("failedGateCount", verdict.failures().size());
        payload.put("metricExecutionStarted", false);
        processRunService.completeStep(
                scope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                verdict.status().name(),
                aggregateRunId,
                PromptQualityVerificationRoutes.readiness(evidencePackage.getPackageId(), scope, aggregateRunId),
                message("enterprise.pqa.runtimeVerification.process.ineligibleSummary"),
                first(nextActions),
                payload,
                operatorId,
                message("enterprise.pqa.runtimeVerification.process.ineligibleBeforeMetrics"));
        processRunService.recordEvent(
                scope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                "OFFICIAL_VERIFICATION_VERDICT",
                payload,
                operatorId,
                message("enterprise.pqa.runtimeVerification.process.verdictPersisted"));
    }
    public void recordReverification(
            PromptQualityProcessScope scope,
            RuntimeEvidenceVerificationRun run,
            List<RuntimeEvidenceReverifyFindingResult> findings,
            boolean linkedCriteriaSatisfied,
            String operatorId) {
        processRunService.completeStep(
                scope,
                PromptQualityProcessCodes.REVERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                run.officialFinalDecision(),
                run.packageId(),
                PromptQualityVerificationRoutes.readiness(run.packageId(), scope, run.aggregateRunId()),
                run.plainSummary(),
                first(run.nextActions()),
                Map.of(
                        "eligible", run.officialVerificationPassed(),
                        "linkedFindingCount", size(findings),
                        "linkedCriteriaSatisfied", linkedCriteriaSatisfied),
                operatorId,
                message("enterprise.pqa.runtimeVerification.process.reverificationCompleted"));
    }

    public void recordFailure(
            PromptQualityProcessScope scope,
            SealedEvidencePackage evidencePackage,
            String operatorId,
            RuntimeException failure) {
        processRunService.failStep(
                scope,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityStateDimension.PROCESS_STAGE.name(),
                PromptQualityProcessCodes.FAILED,
                evidencePackage.getPackageId(),
                PromptQualityVerificationRoutes.readiness(evidencePackage.getPackageId(), scope, null),
                failure == null ? null : failure.getMessage(),
                operatorId,
                message("enterprise.pqa.runtimeVerification.process.failedBeforeCompleteResult"));
    }

    public record AuditSnapshotCommand(
            PromptQualityProcessScope scope,
            OfficialVerificationVerdict verdict,
            PromptQualityAssuranceCase assuranceCase,
            SealedEvidencePackage evidencePackage,
            String aggregateRunId,
            List<RuntimeEvidenceMetricResult> metrics,
            int failedMetricCount,
            List<String> failedMetricCodes,
            List<String> findings,
            List<String> nextActions,
            String requestId,
            String promptHash,
            String contextHash,
            String promptGovernanceVersion,
            String metricSetVersion,
            String engineVersion,
            String operatorId) {
    }
    private boolean shouldComplete(List<PromptQualityProcessStepSnapshot> steps, String stepCode) {
        if (steps == null || steps.isEmpty()) {
            return true;
        }
        return steps.stream()
                .filter(step -> stepCode.equals(step.stepCode()))
                .findFirst()
                .map(step -> !PromptQualityProcessCodes.COMPLETED.equals(normalized(step.executionState())))
                .orElse(true);
    }

    private String runtimeEvidenceState(
            SealedEvidencePackage evidencePackage,
            boolean integrityValid,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (evidencePackage == null || !evidencePackage.isSealed()) {
            return "UNSEALED";
        }
        if (!integrityValid) {
            return "INTEGRITY_ERROR";
        }
        if (promptConsistency != null && (!promptConsistency.passed() || promptConsistency.blocking())) {
            return "WARNING_SIGNALS";
        }
        return "READY_FOR_INSPECTION";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String first(List<String> values) {
        return values == null ? "" : values.stream().filter(StringUtils::hasText).findFirst().orElse("");
    }

    private String firstNonBlank(String first, String fallback) {
        return StringUtils.hasText(first) ? first.trim() : fallback;
    }

    private int size(List<?> values) {
        return values == null ? 0 : values.size();
    }

    private <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}