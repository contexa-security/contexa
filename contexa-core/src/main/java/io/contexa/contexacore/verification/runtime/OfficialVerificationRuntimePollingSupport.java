package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

public final class OfficialVerificationRuntimePollingSupport {

    public static final Duration DEFAULT_ARTIFACT_TIMEOUT = Duration.ofSeconds(180);
    private static final int COMPLETE_ARTIFACT_STABLE_ITERATIONS = 2;
    private static final int PARTIAL_ARTIFACT_STABLE_ITERATIONS = 8;
    private static final int MISSING_ARTIFACT_STABLE_ITERATIONS = 12;

    public enum ArtifactWaitMode {
        ALLOW_PARTIAL_NON_TERMINAL,
        REQUIRE_TERMINAL
    }

    @FunctionalInterface
    public interface ArtifactCompletionProbe {
        boolean isComplete(String requestId);
    }

    private OfficialVerificationRuntimePollingSupport() {
    }

    public static ArtifactSnapshot awaitArtifacts(
            String requestId,
            Duration timeout,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository
    ) {
        return awaitArtifacts(
                requestId,
                timeout,
                analysisEventStore,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                ArtifactWaitMode.ALLOW_PARTIAL_NON_TERMINAL,
                null
        );
    }

    public static ArtifactSnapshot awaitArtifacts(
            String requestId,
            Duration timeout,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            ArtifactCompletionProbe completionProbe
    ) {
        return awaitArtifacts(
                requestId,
                timeout,
                analysisEventStore,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                ArtifactWaitMode.ALLOW_PARTIAL_NON_TERMINAL,
                completionProbe
        );
    }

    public static ArtifactSnapshot awaitArtifacts(
            String requestId,
            Duration timeout,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            ArtifactWaitMode artifactWaitMode
    ) {
        return awaitArtifacts(
                requestId,
                timeout,
                analysisEventStore,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                artifactWaitMode,
                null
        );
    }

    public static ArtifactSnapshot awaitArtifacts(
            String requestId,
            Duration timeout,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            ArtifactWaitMode artifactWaitMode,
            ArtifactCompletionProbe completionProbe
    ) {
        Instant deadline = Instant.now().plus(timeout);
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = List.of();
        SecurityDecisionForwardingOutboxRecord decisionOutbox = null;
        PromptContextAuditForwardingOutboxRecord promptOutbox = null;
        int stableIterationsAfterTerminal = 0;
        int stableIterationsAfterArtifacts = 0;
        int lastEventCount = -1;
        Long lastDecisionOutboxId = null;
        Long lastPromptOutboxId = null;

        while (Instant.now().isBefore(deadline)) {
            events = analysisEventStore.findByRequestId(requestId);
            decisionOutbox = decisionOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(decisionOutbox);
            promptOutbox = promptAuditOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(promptOutbox);

            int currentEventCount = events.size();
            Long currentDecisionOutboxId = decisionOutbox != null ? decisionOutbox.getId() : null;
            Long currentPromptOutboxId = promptOutbox != null ? promptOutbox.getId() : null;
            boolean artifactStateUnchanged = currentEventCount == lastEventCount
                    && Objects.equals(currentDecisionOutboxId, lastDecisionOutboxId)
                    && Objects.equals(currentPromptOutboxId, lastPromptOutboxId);
            if (artifactStateUnchanged) {
                stableIterationsAfterArtifacts++;
            }
            else {
                stableIterationsAfterArtifacts = 0;
                lastEventCount = currentEventCount;
                lastDecisionOutboxId = currentDecisionOutboxId;
                lastPromptOutboxId = currentPromptOutboxId;
            }

            boolean terminal = hasTerminalEvent(events);
            boolean errorTerminal = hasErrorEvent(events);
            boolean completedAnalysis = hasCompletedAnalysisEvent(events);
            boolean externalCompletion = completionProbe != null && completionProbe.isComplete(requestId);
            if (terminal) {
                if (artifactStateUnchanged) {
                    stableIterationsAfterTerminal++;
                }
                else {
                    stableIterationsAfterTerminal = 0;
                }

                if (decisionOutbox != null && promptOutbox != null && stableIterationsAfterTerminal >= COMPLETE_ARTIFACT_STABLE_ITERATIONS) {
                    break;
                }
                if (decisionOutbox != null && stableIterationsAfterTerminal >= PARTIAL_ARTIFACT_STABLE_ITERATIONS) {
                    break;
                }
                if (promptOutbox != null && stableIterationsAfterTerminal >= PARTIAL_ARTIFACT_STABLE_ITERATIONS) {
                    break;
                }
                if (errorTerminal && promptOutbox != null && stableIterationsAfterTerminal >= COMPLETE_ARTIFACT_STABLE_ITERATIONS) {
                    break;
                }
                if (stableIterationsAfterTerminal >= MISSING_ARTIFACT_STABLE_ITERATIONS) {
                    break;
                }
            }
            else if (artifactWaitMode == ArtifactWaitMode.ALLOW_PARTIAL_NON_TERMINAL
                    && (decisionOutbox != null || promptOutbox != null)
                    && stableIterationsAfterArtifacts >= PARTIAL_ARTIFACT_STABLE_ITERATIONS) {
                break;
            }
            else if (artifactWaitMode == ArtifactWaitMode.ALLOW_PARTIAL_NON_TERMINAL
                    && completedAnalysis
                    && stableIterationsAfterArtifacts >= PARTIAL_ARTIFACT_STABLE_ITERATIONS) {
                break;
            }
            else if (artifactWaitMode == ArtifactWaitMode.ALLOW_PARTIAL_NON_TERMINAL
                    && externalCompletion
                    && stableIterationsAfterArtifacts >= COMPLETE_ARTIFACT_STABLE_ITERATIONS) {
                break;
            }

            sleep(250L);
        }

        return new ArtifactSnapshot(events, decisionOutbox, promptOutbox);
    }
    public static List<OfficialVerificationAnalysisEventStore.AnalysisEvent> awaitEvents(
            String requestId,
            Duration timeout,
            OfficialVerificationAnalysisEventStore analysisEventStore
    ) {
        Instant deadline = Instant.now().plus(timeout);
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = List.of();
        int stableIterationsAfterTerminal = 0;
        int lastEventCount = -1;

        while (Instant.now().isBefore(deadline)) {
            events = analysisEventStore.findByRequestId(requestId);
            if (hasTerminalEvent(events)) {
                int currentEventCount = events.size();
                if (currentEventCount == lastEventCount) {
                    stableIterationsAfterTerminal++;
                }
                else {
                    stableIterationsAfterTerminal = 0;
                    lastEventCount = currentEventCount;
                }
                if (stableIterationsAfterTerminal >= 2) {
                    break;
                }
            }
            sleep(250L);
        }
        return events;
    }

    public static SecurityDecisionForwardingOutboxRecord awaitDecisionOutbox(
            String requestId,
            Duration timeout,
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository
    ) {
        Instant deadline = Instant.now().plus(timeout);
        SecurityDecisionForwardingOutboxRecord record = null;
        while (Instant.now().isBefore(deadline)) {
            record = decisionOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(record);
            if (record != null) {
                break;
            }
            sleep(250L);
        }
        return record;
    }

    public static PromptContextAuditForwardingOutboxRecord awaitPromptAuditOutbox(
            String requestId,
            Duration timeout,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository
    ) {
        Instant deadline = Instant.now().plus(timeout);
        PromptContextAuditForwardingOutboxRecord record = null;
        while (Instant.now().isBefore(deadline)) {
            record = promptAuditOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(record);
            if (record != null) {
                break;
            }
            sleep(250L);
        }
        return record;
    }

    public static boolean awaitRepositoryDecisionStateBestEffort(
            String subjectId,
            String requestId,
            Duration timeout,
            ZeroTrustActionRepository zeroTrustActionRepository
    ) {
        Objects.requireNonNull(zeroTrustActionRepository, "zeroTrustActionRepository");
        if (!StringUtils.hasText(subjectId)
                || !StringUtils.hasText(requestId)) {
            return false;
        }

        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysisData =
                    zeroTrustActionRepository.getAnalysisData(subjectId);
            if (analysisData != null
                    && StringUtils.hasText(analysisData.requestId())
                    && requestId.equals(analysisData.requestId())
                    && StringUtils.hasText(analysisData.action())
                    && !ZeroTrustAction.PENDING_ANALYSIS.name().equalsIgnoreCase(analysisData.action())) {
                return true;
            }
            sleep(100L);
        }
        return false;
    }
    private static boolean hasTerminalEvent(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream().anyMatch(event ->
                "DECISION_APPLIED".equalsIgnoreCase(event.type()) || "ERROR".equalsIgnoreCase(event.type()));
    }

    private static boolean hasErrorEvent(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream().anyMatch(event -> "ERROR".equalsIgnoreCase(event.type()));
    }

    private static boolean hasCompletedAnalysisEvent(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream().anyMatch(event ->
                "COMPLETED".equalsIgnoreCase(event.status())
                        && ("LAYER1_COMPLETE".equalsIgnoreCase(event.type())
                        || "LAYER2_COMPLETE".equalsIgnoreCase(event.type())
                        || "LLM_EXECUTION_COMPLETE".equalsIgnoreCase(event.type())));
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }

    public record ArtifactSnapshot(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox
    ) {
    }
}


