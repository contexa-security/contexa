package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptPreflightService;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class OfficialVerificationExecutionLedger extends AbstractPromptQualityRuntimeEvidenceSupport {

    private static final Logger log = LoggerFactory.getLogger(OfficialVerificationExecutionLedger.class);
    private static final DateTimeFormatter GENERATED_AT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");

    private final OfficialVerificationExecutionLockService executionLockService;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialVerificationMetricContract metricContract;
    private final OfficialVerificationEvidencePreflight evidencePreflight;

    public OfficialVerificationExecutionLedger(
            OfficialVerificationExecutionLockService executionLockService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialVerificationMetricContract metricContract,
            OfficialVerificationEvidencePreflight evidencePreflight,
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver) {
        super(objectMapper, messageResolver);
        this.executionLockService = Objects.requireNonNull(executionLockService, "executionLockService");
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.metricContract = Objects.requireNonNull(metricContract, "metricContract");
        this.evidencePreflight = Objects.requireNonNull(evidencePreflight, "evidencePreflight");
    }

    public OfficialVerificationExecutionLockService.ExecutionRecord start(
            RuntimeEvidenceVerificationRequest request,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            ProtectableResourceDescriptor descriptor) {
        return executionLockService.start(executionRequest(request, evidence, descriptor));
    }

    public OfficialVerificationExecutionLockService.ExecutionRecord startFailureRecord(
            RuntimeEvidenceVerificationRequest request,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence) {
        try {
            OfficialVerificationExecutionLockService.ExecutionRecord record = start(request, evidence, null);
            return record.acquired() ? record : null;
        }
        catch (RuntimeException failure) {
            log.error(
                    "PQA official verification pre-ledger failure record could not be created. packageId={}, requestPath={}, resourceId={}, httpMethod={}",
                    evidence.evidencePackage().getPackageId(),
                    evidence.requestPath(),
                    evidence.resourceId(),
                    evidence.httpMethod(),
                    failure);
            return null;
        }
    }

    public void replacePreviousDiagnostics(OfficialVerificationEvidencePreflight.EvidenceContext evidence) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        List<String> replacedPackageIds = operatorSnapshotService.replaceDiagnosticsForQualityTarget(
                evidencePackage.getTenantId(),
                evidencePackage.getPackageId(),
                evidence.actualResourceId(),
                evidence.requestPath(),
                evidence.httpMethod());
        executionLockService.deleteFinishedExecutionsForPackages(
                evidencePackage.getTenantId(), replacedPackageIds);
    }

    public OfficialVerificationExecutionStatus status(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return OfficialVerificationExecutionStatus.empty(packageId);
        }
        return evidencePreflight.findByPackageId(packageId.trim())
                .filter(evidencePackage -> StringUtils.hasText(evidencePackage.getTenantId()))
                .map(evidencePackage -> executionLockService.status(
                        evidencePackage.getTenantId(), evidencePackage.getPackageId()))
                .orElseGet(() -> OfficialVerificationExecutionStatus.empty(packageId));
    }

    public OfficialVerificationExecutionStatus status(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(aggregateRunId)) {
            return status(packageId);
        }
        return evidencePreflight.findByPackageId(packageId.trim())
                .filter(evidencePackage -> StringUtils.hasText(evidencePackage.getTenantId()))
                .map(evidencePackage -> executionLockService.status(
                        evidencePackage.getTenantId(), evidencePackage.getPackageId(), aggregateRunId.trim()))
                .orElseGet(() -> OfficialVerificationExecutionStatus.empty(packageId));
    }

    public RuntimeEvidenceVerificationRun idempotentRun(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence) {
        if (record.completed()) {
            return executionLockService.completedResult(record)
                    .orElseGet(() -> statusRun(
                            record,
                            evidence,
                            message("enterprise.pqa.runtimeVerification.status.diagnosticMissing"),
                            message("enterprise.pqa.runtimeVerification.status.rerunReplaces")));
        }
        if (record.failed()) {
            return statusRun(
                    record,
                    evidence,
                    firstNonBlank(
                            record.failureReason(),
                            message("enterprise.pqa.runtimeVerification.status.previousFailed")),
                    firstNonBlank(
                            record.retryInstruction(),
                            message("enterprise.pqa.runtimeVerification.status.retryAfterFailure")));
        }
        return statusRun(
                record,
                evidence,
                message("enterprise.pqa.runtimeVerification.status.alreadyRunning"),
                message("enterprise.pqa.runtimeVerification.status.waitRunning"));
    }

    public void transition(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            String state,
            int progressPercent,
            String detail) {
        executionLockService.transition(record, state, progressPercent, detail);
    }

    public void transitionMessage(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            String state,
            int progressPercent,
            String messageKey,
            Object... args) {
        transition(record, state, progressPercent, message(messageKey, args));
    }

    public void markMetricsRunning(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            String aggregateRunId) {
        executionLockService.markMetricsRunning(record, aggregateRunId, metricContract.expectedMetricCodes());
    }

    public void markCompleted(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            String aggregateRunId,
            RuntimeEvidenceVerificationRun run) {
        executionLockService.markCompleted(record, aggregateRunId, run);
    }

    public void markFailed(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            RuntimeException failure) {
        boolean recoverable = recoverable(failure);
        executionLockService.markFailed(record, failure, recoverable, retryInstruction(recoverable));
    }

    public String failureAggregateRunId(
            SealedEvidencePackage evidencePackage,
            OfficialVerificationExecutionLockService.ExecutionRecord record) {
        return "osev-failed-" + safe(evidencePackage == null ? null : evidencePackage.getPackageId())
                + "-lock-" + (record == null ? "unknown" : record.id())
                + "-attempt-" + (record == null ? 1 : record.attemptNo());
    }

    private OfficialVerificationExecutionLockService.ExecutionRequest executionRequest(
            RuntimeEvidenceVerificationRequest request,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            ProtectableResourceDescriptor descriptor) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        Map<String, String> components = new LinkedHashMap<>();
        components.put("packageId", safe(evidencePackage.getPackageId()));
        components.put("sealedEvidenceHash", safe(evidencePackage.getPackageHash()));
        components.put("promptHash", safe(firstNonBlank(
                evidencePackage.getPromptHash(), text(evidence.promptMetadata(), "promptHash"))));
        components.put("promptGovernanceVersion", safe(
                evidencePreflight.promptGovernanceVersion(evidence.promptMetadata())));
        components.put("metricSetVersion", metricContract.metricSetVersion());
        components.put("officialVerificationEngineVersion", metricContract.engineVersion());
        components.put("actualPromptProblemLedgerContractVersion",
                OfficialVerificationOperatorSnapshotService.ACTUAL_PROMPT_PROBLEM_LEDGER_CONTRACT_VERSION);
        components.put("resourceTemplateId", safe(evidencePreflight.resourceTemplateId(
                evidence.requestFacts(), evidence.promptMetadata(), descriptor, evidence.resourceId())));
        components.put("actualResourceId", safe(evidence.actualResourceId()));
        components.put("httpMethod", safe(evidence.httpMethod()));
        String fingerprintJson = writeJson(components);
        String key = "pqa-official:" + sha256(fingerprintJson);
        return new OfficialVerificationExecutionLockService.ExecutionRequest(
                key,
                key,
                evidencePackage.getPackageId(),
                evidencePackage.getTenantId(),
                evidence.operatorId(),
                request != null && request.forceReverification(),
                request == null ? null : request.reverificationReason(),
                fingerprintJson);
    }

    private RuntimeEvidenceVerificationRun statusRun(
            OfficialVerificationExecutionLockService.ExecutionRecord record,
            OfficialVerificationEvidencePreflight.EvidenceContext evidence,
            String summary,
            String nextAction) {
        SealedEvidencePackage evidencePackage = evidence.evidencePackage();
        String state = firstNonBlank(record.state(), "RUNNING");
        String runId = firstNonBlank(
                record.aggregateRunId(),
                "pending-" + record.idempotencyKey().substring(
                        0, Math.min(record.idempotencyKey().length(), 24)));
        String requestId = firstNonBlank(
                text(evidence.requestFacts(), "requestId"),
                text(evidence.promptMetadata(), "requestId"),
                evidencePackage.getCorrelationId());
        String promptHash = firstNonBlank(
                evidencePackage.getPromptHash(), text(evidence.promptMetadata(), "promptHash"));
        String contextHash = OfficialContextHashStateResolver.resolve(
                evidence.requestFacts(),
                evidence.promptMetadata(),
                evidencePackage.getCanonicalContextJson()).contextHash();
        return new RuntimeEvidenceVerificationRun(
                runId,
                evidencePackage.getPackageId(),
                generatedAt(),
                null,
                summary,
                metricContract.expectedMetricCodes().size(),
                0,
                0,
                evidencePackage.getTenantId(),
                evidencePackage.getUserId(),
                evidence.requestPath(),
                evidence.resourceId(),
                evidence.httpMethod(),
                List.of(),
                List.of(),
                record.failed() ? List.of(summary) : List.of(),
                List.of(nextAction),
                requestId,
                promptHash,
                contextHash,
                List.of(),
                List.of(),
                List.of(),
                evidence.promptConsistency(),
                state,
                record.progressPercent(),
                null);
    }

    private boolean recoverable(RuntimeException failure) {
        return !(failure instanceof FinalPromptPreflightService.FinalPromptPreflightException);
    }

    private String retryInstruction(boolean recoverable) {
        return recoverable
                ? message("enterprise.pqa.runtimeVerification.retry.recoverable")
                : message("enterprise.pqa.runtimeVerification.retry.terminal");
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        }
        catch (Exception exception) {
            throw new IllegalStateException(
                    "Official verification idempotency fingerprint cannot be serialized.", exception);
        }
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(
                    (value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private String generatedAt() {
        return LocalDateTime.now(KOREA_ZONE).format(GENERATED_AT);
    }
}
