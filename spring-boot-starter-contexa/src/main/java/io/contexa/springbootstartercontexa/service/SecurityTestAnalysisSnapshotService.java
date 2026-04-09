package io.contexa.springbootstartercontexa.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEvent;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEventPublisher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SecurityTestAnalysisSnapshotService {

    private final ZeroTrustActionRepository actionRepository;
    private final LlmAnalysisEventPublisher llmAnalysisEventPublisher;

    public AnalysisSnapshot resolveSnapshot(String userId, String requestId) {
        ZeroTrustAnalysisData repositoryData = StringUtils.hasText(userId)
                ? actionRepository.getAnalysisData(userId)
                : ZeroTrustAnalysisData.pending();

        AnalysisSnapshot repositorySnapshot = fromRepository(repositoryData, requestId);
        if (!StringUtils.hasText(requestId) || repositorySnapshot.requestLinked()) {
            return repositorySnapshot;
        }

        List<LlmAnalysisEvent> requestEvents = resolveRequestEvents(userId, requestId);
        if (!requestEvents.isEmpty()) {
            AnalysisSnapshot eventSnapshot = fromEvents(requestId, requestEvents);
            if (eventSnapshot.hasAnalysisSignal()) {
                return eventSnapshot;
            }
        }

        return repositorySnapshot;
    }

    private List<LlmAnalysisEvent> resolveRequestEvents(String userId, String requestId) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(requestId)) {
            return List.of();
        }
        return llmAnalysisEventPublisher.getRecentEvents(userId).stream()
                .filter(event -> requestId.equals(event.getRequestId()) || requestId.equals(event.getCorrelationId()))
                .toList();
    }

    private AnalysisSnapshot fromRepository(ZeroTrustAnalysisData data, String requestedRequestId) {
        String action = data != null ? data.action() : null;
        boolean analyzed = StringUtils.hasText(action) && !ZeroTrustAction.PENDING_ANALYSIS.name().equals(action);
        boolean requestLinked = StringUtils.hasText(requestedRequestId)
                ? requestedRequestId.equals(data != null ? data.requestId() : null)
                : StringUtils.hasText(data != null ? data.requestId() : null);
        String analysisStatus = analyzed ? "ANALYZED" : "NOT_ANALYZED";

        return new AnalysisSnapshot(
                requestedRequestId,
                data != null ? data.requestId() : null,
                action != null ? action : ZeroTrustAction.PENDING_ANALYSIS.name(),
                defaultNumber(data != null ? data.riskScore() : null),
                defaultNumber(data != null ? data.confidence() : null),
                data != null ? data.threatEvidence() : null,
                data != null ? data.analysisDepth() : null,
                data != null ? data.updatedAt() : null,
                data != null ? data.reasoning() : null,
                data != null ? data.reasoningSummary() : null,
                data != null ? data.contextBindingHash() : null,
                data != null ? data.llmProposedAction() : null,
                analysisStatus,
                requestLinked,
                analyzed ? "ACTION_REPOSITORY" : "PENDING",
                0
        );
    }

    private AnalysisSnapshot fromEvents(String requestedRequestId, List<LlmAnalysisEvent> events) {
        LlmAnalysisEvent latestActionEvent = events.stream()
                .filter(event -> StringUtils.hasText(event.getAction()))
                .max(Comparator.comparingLong(event -> event.getTimestamp() != null ? event.getTimestamp() : 0L))
                .orElse(null);

        LlmAnalysisEvent latestRiskEvent = events.stream()
                .filter(event -> event.getRiskScore() != null || event.getConfidence() != null)
                .max(Comparator.comparingLong(event -> event.getTimestamp() != null ? event.getTimestamp() : 0L))
                .orElse(null);

        LlmAnalysisEvent latestReasoningEvent = events.stream()
                .filter(event -> StringUtils.hasText(event.getReasoning()) || StringUtils.hasText(event.getReasoningSummary()))
                .max(Comparator.comparingLong(event -> event.getTimestamp() != null ? event.getTimestamp() : 0L))
                .orElse(null);

        String action = latestActionEvent != null && StringUtils.hasText(latestActionEvent.getAction())
                ? latestActionEvent.getAction()
                : ZeroTrustAction.PENDING_ANALYSIS.name();

        String analysisStatus = StringUtils.hasText(action) && !ZeroTrustAction.PENDING_ANALYSIS.name().equals(action)
                ? "ANALYZED"
                : "IN_PROGRESS";

        return new AnalysisSnapshot(
                requestedRequestId,
                requestedRequestId,
                action,
                defaultNumber(latestRiskEvent != null ? latestRiskEvent.getRiskScore() : null),
                defaultNumber(latestRiskEvent != null ? latestRiskEvent.getConfidence() : null),
                firstNonBlank(
                        latestActionEvent != null ? latestActionEvent.getMitre() : null,
                        latestRiskEvent != null ? latestRiskEvent.getMitre() : null,
                        metadataText(latestActionEvent, "threatEvidence"),
                        metadataText(latestRiskEvent, "threatEvidence")),
                resolveAnalysisDepth(events),
                latestTimestamp(events),
                latestReasoningEvent != null ? latestReasoningEvent.getReasoning() : null,
                latestReasoningEvent != null ? latestReasoningEvent.getReasoningSummary() : null,
                firstNonBlank(
                        latestActionEvent != null ? latestActionEvent.getContextBindingHash() : null,
                        latestRiskEvent != null ? latestRiskEvent.getContextBindingHash() : null,
                        metadataText(latestActionEvent, "contextBindingHash"),
                        metadataText(latestRiskEvent, "contextBindingHash")),
                action,
                analysisStatus,
                true,
                "EVENT_STREAM",
                events.size()
        );
    }

    private Integer resolveAnalysisDepth(List<LlmAnalysisEvent> events) {
        boolean layer2Seen = events.stream().anyMatch(event ->
                LlmAnalysisEvent.Layer.LAYER2.equals(event.getLayer())
                        || LlmAnalysisEvent.EventType.LAYER2_START.equals(event.getType())
                        || LlmAnalysisEvent.EventType.LAYER2_COMPLETE.equals(event.getType()));
        if (layer2Seen) {
            return 2;
        }
        boolean layer1Seen = events.stream().anyMatch(event ->
                LlmAnalysisEvent.Layer.LAYER1.equals(event.getLayer())
                        || LlmAnalysisEvent.EventType.LAYER1_START.equals(event.getType())
                        || LlmAnalysisEvent.EventType.LAYER1_COMPLETE.equals(event.getType()));
        return layer1Seen ? 1 : null;
    }

    private String latestTimestamp(List<LlmAnalysisEvent> events) {
        return events.stream()
                .map(LlmAnalysisEvent::getTimestamp)
                .filter(timestamp -> timestamp != null && timestamp > 0)
                .max(Long::compareTo)
                .map(Instant::ofEpochMilli)
                .map(Instant::toString)
                .orElse(null);
    }

    private Double defaultNumber(Double value) {
        return value != null ? value : 0.0;
    }

    private String metadataText(LlmAnalysisEvent event, String key) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    public record AnalysisSnapshot(
            String selectedRequestId,
            String requestId,
            String action,
            Double riskScore,
            Double confidence,
            String threatEvidence,
            Integer analysisDepth,
            String updatedAt,
            String reasoning,
            String reasoningSummary,
            String contextBindingHash,
            String llmProposedAction,
            String analysisStatus,
            boolean requestLinked,
            String analysisSource,
            int linkedEventCount
    ) {
        public boolean hasAnalysisSignal() {
            return StringUtils.hasText(action)
                    && (!ZeroTrustAction.PENDING_ANALYSIS.name().equals(action)
                    || linkedEventCount > 0
                    || StringUtils.hasText(reasoningSummary)
                    || StringUtils.hasText(reasoning));
        }

        public Map<String, Object> toMap(String userId) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("userId", userId);
            response.put("selectedRequestId", selectedRequestId);
            response.put("requestId", requestId);
            response.put("action", action);
            response.put("riskScore", riskScore);
            response.put("confidence", confidence);
            response.put("analysisStatus", analysisStatus);
            response.put("requestLinked", requestLinked);
            response.put("analysisSource", analysisSource);
            response.put("linkedEventCount", linkedEventCount);
            response.put("analysisDepth", analysisDepth);
            response.put("updatedAt", updatedAt);
            response.put("reasoning", reasoning);
            response.put("reasoningSummary", reasoningSummary);
            response.put("contextBindingHash", contextBindingHash);
            response.put("llmProposedAction", llmProposedAction);
            response.put("threatEvidence", threatEvidence);
            return response;
        }
    }
}