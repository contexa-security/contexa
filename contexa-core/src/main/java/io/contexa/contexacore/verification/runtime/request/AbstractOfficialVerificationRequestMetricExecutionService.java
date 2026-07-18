package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Transactional(transactionManager = "contexaTransactionManager")
public abstract class AbstractOfficialVerificationRequestMetricExecutionService<R extends OfficialVerificationRunView, E>
        extends AbstractOfficialVerificationMetricExecutionService<R>
        implements OfficialVerificationRequestMetricExecutor<R> {

    protected record RequestMetricExecutionArtifacts(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
    }

    protected record RequestMetricExecutionState<E>(
            String userId,
            String verificationUserId,
            E endpoint,
            String requestId,
            int runOrdinal,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request,
            Instant startedAt,
            Instant completedAt,
            long processingTimeMs,
            Map<String, Object> invocation,
            RequestMetricExecutionArtifacts artifacts
    ) {
    }

    protected AbstractOfficialVerificationRequestMetricExecutionService(
            String notFoundMetricCode,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper,
            Function<R, String> runIdExtractor,
            Function<R, String> startedAtExtractor
    ) {
        super(
                notFoundMetricCode,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                analysisEventStore,
                probeClient,
                objectMapper,
                runIdExtractor,
                startedAtExtractor
        );
    }

    protected final synchronized R executeRunTemplate(
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
        E endpoint = resolveEndpoint(endpointKey, resourceId, requestPath);
        String requestId = nextMetricRequestId(requestIdPrefix());
        String verificationUserId = resolveVerificationUserId(userId, requestId);
        beforeInvocation(
                endpoint,
                userId,
                verificationUserId,
                requestId,
                requestedRunCount,
                contaminationSeed,
                baselineSeedRequested,
                request
        );
        Instant startedAt = Instant.now();
        Map<String, Object> invocation = invokeProbe(
                endpoint,
                requestId,
                verificationUserId,
                requestedRunCount,
                contaminationSeed,
                baselineSeedRequested,
                request
        );
        OfficialVerificationRuntimePollingSupport.ArtifactSnapshot artifactSnapshot = OfficialVerificationRuntimePollingSupport.awaitArtifacts(
                requestId,
                artifactTimeout(),
                analysisEventStore,
                decisionOutboxRepository,
                promptAuditOutboxRepository
        );
        Instant completedAt = Instant.now();
        RequestMetricExecutionArtifacts artifacts = new RequestMetricExecutionArtifacts(
                artifactSnapshot.events(),
                artifactSnapshot.decisionOutbox(),
                artifactSnapshot.promptOutbox(),
                parseJson(artifactSnapshot.decisionOutbox() != null ? artifactSnapshot.decisionOutbox().getPayloadJson() : null),
                parseJson(artifactSnapshot.promptOutbox() != null ? artifactSnapshot.promptOutbox().getPayloadJson() : null)
        );
        artifacts = refineArtifacts(requestId, artifacts);
        RequestMetricExecutionState<E> state = new RequestMetricExecutionState<>(
                userId,
                verificationUserId,
                endpoint,
                requestId,
                nextRunOrdinal(userId),
                requestedRunCount,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                request,
                startedAt,
                completedAt,
                Math.max(0L, Duration.between(startedAt, completedAt).toMillis()),
                invocation != null ? invocation : Map.of(),
                artifacts
        );
        R run = buildRunRecord(state);
        storeRun(userId, run);
        return run;
    }

    protected RequestMetricExecutionArtifacts refineArtifacts(String requestId, RequestMetricExecutionArtifacts artifacts) {
        return artifacts;
    }

    protected Duration artifactTimeout() {
        return OfficialVerificationRuntimePollingSupport.DEFAULT_ARTIFACT_TIMEOUT;
    }

    protected String resolveVerificationUserId(String userId, String requestId) {
        return userId;
    }

    protected void beforeInvocation(
            E endpoint,
            String userId,
            String verificationUserId,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
    }

    protected abstract String requestIdPrefix();

    protected abstract E resolveEndpoint(String endpointKey, String resourceId, String requestPath);

    protected abstract Map<String, Object> invokeProbe(
            E endpoint,
            String requestId,
            String verificationUserId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    );

    protected abstract R buildRunRecord(RequestMetricExecutionState<E> state);
}



