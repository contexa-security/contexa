package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationEirExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationEirExecutionService.EirRunRecord, OfficialVerificationEirExecutionService.EndpointDefinition> implements OfficialVerificationEirExecutor {

    private final OfficialVerificationEirEvidenceFactory evidenceFactory = new OfficialVerificationEirEvidenceFactory();

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "EIR",
                    OfficialVerificationEirExecutionService.class.getName(),
                    "executeRun / buildRequestFacts / buildRawEvidence",
                    "metricCode"
            );

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String DELEGATED_HEADER = "X-Contexa-Delegated";
    private static final String AGENT_ID_HEADER = "X-Contexa-Agent-Id";
    private static final String OBJECTIVE_ID_HEADER = "X-Contexa-Objective-Id";
    private static final String OBJECTIVE_FAMILY_HEADER = "X-Contexa-Objective-Family";
    private static final String OBJECTIVE_SUMMARY_HEADER = "X-Contexa-Objective-Summary";
    private static final String ALLOWED_OPERATIONS_HEADER = "X-Contexa-Allowed-Operations";
    private static final String ALLOWED_RESOURCES_HEADER = "X-Contexa-Allowed-Resources";
    private static final String APPROVAL_REQUIRED_HEADER = "X-Contexa-Approval-Required";
    private static final String PRIVILEGED_EXPORT_ALLOWED_HEADER = "X-Contexa-Privileged-Export-Allowed";
    private static final String CONTAINMENT_ONLY_HEADER = "X-Contexa-Containment-Only";
    private static final String DELEGATION_EXPIRES_AT_HEADER = "X-Contexa-Delegation-Expires-At";
    private static final String OFFICIAL_VERIFICATION_AGENT_ID = "official-verification-agent";
    static final String OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY = "OFFICIAL_VERIFICATION";
    private static final String OFFICIAL_VERIFICATION_DELEGATION_EXPIRES_AT = "2026-04-05T00:00:00Z";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String DEVICE_ID_HEADER = "X-Device-Id";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    static final String EIR_CLIENT_IP = "192.168.1.100";
    private static final String EIR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String EIR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String EIR_DEVICE_ID = "official-verification-eir-admin-browser";

    public OfficialVerificationEirExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper
    ) {
        super("EIR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, EirRunRecord::runId, EirRunRecord::startedAt);
    }

    @Override
    public synchronized EirRunRecord executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        return executeRunTemplate(userId, endpointKey, resourceId, requestPath, requestedRunCount, rerun, contaminationSeed, baselineSeedRequested, request);
    }

    @Override
    protected String requestIdPrefix() {
        return "enterprise-eir-";
    }

    @Override
    protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.resolveProbeTarget(endpointKey, resourceId, requestPath, List.of("normal", "delegated", "sensitive", "critical"));
        return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
            case "delegated" -> "Delegated Resource";
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, replayTarget.requestPath(), replayTarget.resourceId());
    }
    @Override
    protected EirRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        List<EirCheckResult> checks = evidenceFactory.buildChecks(
                state.requestId(),
                state.endpoint(),
                state.invocation(),
                state.artifacts().events(),
                state.contaminationSeed(),
                state.baselineSeedRequested()
        );
        int passedChecks = (int) checks.stream().filter(EirCheckResult::pass).count();
        int totalChecks = checks.size();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        return assembleRunRecord(state, checks, passedChecks, totalChecks, score);
    }

    private EirRunRecord assembleRunRecord(RequestMetricExecutionState<EndpointDefinition> state, List<EirCheckResult> checks, int passedChecks, int totalChecks, double score) {
        return new EirRunRecord(
                UUID.randomUUID().toString(),
                state.runOrdinal(),
                state.endpoint().key(),
                state.endpoint().label(),
                state.requestId(),
                score,
                passedChecks,
                totalChecks,
                state.processingTimeMs(),
                score >= 95.0d ? "Threshold passed" : "Threshold failed",
                score >= 95.0d ? "success" : "error",
                score >= 95.0d
                        ? "Request, event, and decision fields stayed aligned through the final decision."
                        : "One or more request, event, or decision fields were missing or diverged during execution.",
                KOREA_TIME.format(state.startedAt()),
                KOREA_TIME.format(state.completedAt()),
                checks,
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        evidenceFactory.buildRequestFacts(
                                state.endpoint(),
                                state.userId(),
                                state.requestId(),
                                state.invocation(),
                                state.requestedRunCount(),
                                state.rerun(),
                                state.contaminationSeed(),
                                state.baselineSeedRequested()
                        ),
                        state.request()
                ),
                evidenceFactory.buildEventFacts(state.artifacts().events()),
                evidenceFactory.buildPromptFacts(state.artifacts().decisionPayload(), state.artifacts().promptPayload()),
                evidenceFactory.buildAnalysisFacts(state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().events()),
                state.artifacts().events().stream().map(evidenceFactory::toEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        evidenceFactory.buildRawEvidence(
                                state.endpoint(),
                                state.userId(),
                                state.requestedRunCount(),
                                state.rerun(),
                                state.contaminationSeed(),
                                state.baselineSeedRequested(),
                                state.invocation(),
                                state.artifacts().events(),
                                state.artifacts().decisionOutbox(),
                                state.artifacts().promptOutbox(),
                                state.artifacts().decisionPayload(),
                                state.artifacts().promptPayload()
                        ),
                        state.request()
                )
        );
    }

    @Override
    protected Map<String, Object> invokeProbe(
            EndpointDefinition endpoint,
            String requestId,
            String verificationUserId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        return invokeProbeRequest(request, endpoint.path(), headers -> forwardHeaders(
                        headers,
                        request,
                        requestId,
                        verificationUserId,
                        endpoint,
                        requestedRunCount,
                        contaminationSeed,
                        baselineSeedRequested
        ));
    }

    private void forwardHeaders(
            OfficialVerificationProbeHeaders headers,
            OfficialVerificationExecutionRequest request,
            String requestId,
            String userId,
            EndpointDefinition endpoint,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set(OfficialVerificationProbeHeaders.USER_AGENT, EIR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, EIR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, EIR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, EIR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, EIR_USER_AGENT_LABEL);
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, endpoint != null && StringUtils.hasText(endpoint.resourceId()) ? endpoint.resourceId().trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId));
        applyDelegationHeaders(headers, endpoint);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }

    private void applyDelegationHeaders(OfficialVerificationProbeHeaders headers, EndpointDefinition endpoint) {
        if (endpoint == null || !evidenceFactory.sameValue("delegated", endpoint.key())) {
            return;
        }
        headers.set(DELEGATED_HEADER, "true");
        headers.set(AGENT_ID_HEADER, OFFICIAL_VERIFICATION_AGENT_ID);
        headers.set(OBJECTIVE_ID_HEADER, "official-verification-delegated-" + endpoint.resourceId());
        headers.set(OBJECTIVE_FAMILY_HEADER, OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY);
        headers.set(OBJECTIVE_SUMMARY_HEADER, "Validate delegated execution lineage for the official enterprise verification probe.");
        headers.set(ALLOWED_OPERATIONS_HEADER, "READ,VERIFY");
        headers.set(ALLOWED_RESOURCES_HEADER, endpoint.resourceId());
        headers.set(APPROVAL_REQUIRED_HEADER, "true");
        headers.set(PRIVILEGED_EXPORT_ALLOWED_HEADER, "false");
        headers.set(CONTAINMENT_ONLY_HEADER, "true");
        headers.set(DELEGATION_EXPIRES_AT_HEADER, OFFICIAL_VERIFICATION_DELEGATION_EXPIRES_AT);
    }
    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record EirRunSummary(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String startedAt,
            String completedAt) {
    }

    public record EirRunRecord(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String message,
            String startedAt,
            String completedAt,
            List<EirCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<EirEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<EirCheckResult, EirEventItem> {

        public EirRunSummary toSummary() {
            return new EirRunSummary(
                    runId,
                    round,
                    endpointKey,
                    endpointLabel,
                    requestId,
                    score,
                    passedChecks,
                    totalChecks,
                    processingTimeMs,
                    state,
                    stateTone,
                    startedAt,
                    completedAt
            );
        }
    }

    public record EirCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record EirEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}



















