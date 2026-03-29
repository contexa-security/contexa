package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@RequiredArgsConstructor
public class ColdPathEventProcessor implements IPathProcessor {

    private final Layer1ContextualStrategy contextualStrategy;
    private final Layer2ExpertStrategy expertStrategy;
    private final LlmAnalysisEventListener llmAnalysisEventListener;

    private static final int ESCALATE_SAMPLE_WINDOW = 100;
    private static final double ESCALATE_RATE_THRESHOLD = 0.5;
    private final AtomicInteger escalateCount = new AtomicInteger(0);
    private final AtomicInteger totalAnalysisCount = new AtomicInteger(0);

    @Override
    public ProcessingResult processEvent(SecurityEvent event, double riskScore) {
        long startTime = System.currentTimeMillis();

        try {
            String userId = event.getUserId();
            if (userId == null) {
                log.error("[ColdPath] Event missing userId: eventId={}", event.getEventId());
                return ProcessingResult.failure(
                        ProcessingResult.ProcessingPath.COLD_PATH,
                        "Missing userId"
                );
            }

            String requestPath = extractRequestPath(event);
            String analysisRequirement = extractAnalysisRequirement(event);
            Map<String, Object> listenerMetadata = buildListenerMetadata(event, requestPath, analysisRequirement);
            publishContextCollected(userId, requestPath, analysisRequirement, listenerMetadata);

            ProcessingResult result = ProcessingResult.builder()
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .currentRiskLevel(riskScore)
                    .success(true)
                    .build();
            result.addAnalysisData("analysisRequirement", analysisRequirement);

            ThreatAnalysisResult analysisResult = performTieredAIAnalysis(event, riskScore, listenerMetadata);
            result.setAction(analysisResult.getAction());
            result.setProposedAction(analysisResult.getProposedAction());
            result.setConfidence(analysisResult.getConfidence());
            result.setLlmAuditRiskScore(analysisResult.getFinalScore());
            result.setLlmAuditConfidence(analysisResult.getLlmAuditConfidence());
            result.setReasoning(analysisResult.getReasoning());
            result.setThreatIndicators(analysisResult.getIndicators());
            result.setRecommendedActions(new ArrayList<>(analysisResult.getRecommendedActions()));
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());
            result.setAutonomyConstraintApplied(analysisResult.getAutonomyConstraintApplied());
            result.setAutonomyConstraintReasons(analysisResult.getAutonomyConstraintReasons());
            result.setAutonomyConstraintSummary(analysisResult.getAutonomyConstraintSummary());
            result.addAnalysisData("aiAssessment", analysisResult);
            result.addAnalysisData("llmAuditRiskScore", analysisResult.getFinalScore());
            result.addAnalysisData("confidence", analysisResult.getConfidence());
            result.addAnalysisData("llmAuditConfidence", analysisResult.getLlmAuditConfidence());
            result.addAnalysisData("llmProposedAction", analysisResult.getProposedAction());
            result.addAnalysisData("autonomousEnforcementAction", analysisResult.getAction());
            result.addAnalysisData("autonomyConstraintApplied", analysisResult.getAutonomyConstraintApplied());
            result.addAnalysisData("autonomyConstraintSummary", analysisResult.getAutonomyConstraintSummary());

            long processingTime = System.currentTimeMillis() - startTime;
            result.setProcessingTimeMs(processingTime);
            result.setProcessedAt(LocalDateTime.now());
            result.setStatus(ProcessingResult.ProcessingStatus.SUCCESS);

            return result;

        } catch (Exception e) {
            log.error("[ColdPath] Processing failed: eventId={}", event.getEventId(), e);
            publishError(event.getUserId(), "AI analysis failed: " + e.getMessage(), buildErrorMetadata(event));
            return ProcessingResult.failure(
                    ProcessingResult.ProcessingPath.COLD_PATH,
                    "AI analysis failed: " + e.getMessage()
            );
        }
    }

    private ThreatAnalysisResult performTieredAIAnalysis(SecurityEvent event, double riskScore, Map<String, Object> listenerMetadata) {
        ThreatAnalysisResult result = new ThreatAnalysisResult();
        result.setBaseScore(riskScore);
        String userId = event.getUserId();
        String requestPath = extractRequestPath(event);

        try {
            ThreatAssessment layer1Assessment = null;
            if (contextualStrategy != null) {
                publishLayer1Start(userId, requestPath, listenerMetadata);
                long layer1StartTime = System.currentTimeMillis();
                layer1Assessment = contextualStrategy.evaluate(event);
                long layer1ElapsedMs = System.currentTimeMillis() - layer1StartTime;

                if (!layer1Assessment.isShouldEscalate()) {
                    result.setFinalScore(layer1Assessment.resolveAuditRiskScore());
                    result.setConfidence(layer1Assessment.getConfidence());
                    result.setLlmAuditConfidence(layer1Assessment.resolveAuditConfidence());
                    result.addIndicators(layer1Assessment.getIndicators());
                    result.addRecommendedActions(layer1Assessment.getRecommendedActions());
                    result.setAnalysisDepth(1);
                    result.setProposedAction(layer1Assessment.getAction());
                    result.setAction(resolveEnforcedAction(layer1Assessment));
                    result.setReasoning(layer1Assessment.getReasoning());
                    result.setAutonomyConstraintApplied(layer1Assessment.getAutonomyConstraintApplied());
                    result.setAutonomyConstraintReasons(layer1Assessment.getAutonomyConstraintReasons());
                    result.setAutonomyConstraintSummary(layer1Assessment.getAutonomyConstraintSummary());
                    String reasoning = layer1Assessment.getReasoning() != null
                            ? layer1Assessment.getReasoning() : "Layer1 analysis completed";
                    publishLayer1Complete(
                            userId,
                            layer1Assessment.getAction(),
                            layer1Assessment.resolveAuditRiskScore(),
                            layer1Assessment.resolveAuditConfidence(),
                            reasoning,
                            extractMitre(layer1Assessment),
                            layer1ElapsedMs,
                            augmentAssessmentMetadata(listenerMetadata, layer1Assessment, "LAYER1"));

                    publishDecisionApplied(
                            userId,
                            result.getAction(),
                            "LAYER1",
                            requestPath,
                            augmentDecisionMetadata(listenerMetadata, result, "LAYER1"));

                    return result;
                }

                publishLayer1Complete(
                        userId,
                        ZeroTrustAction.ESCALATE.name(),
                        layer1Assessment.resolveAuditRiskScore(),
                        layer1Assessment.resolveAuditConfidence(),
                        "Escalating to Layer2 for deeper analysis",
                        "none",
                        layer1ElapsedMs,
                        augmentAssessmentMetadata(listenerMetadata, layer1Assessment, "LAYER1"));

                event.getMetadata().put("layer1Assessment", layer1Assessment);
            }

            int total = totalAnalysisCount.incrementAndGet();
            if (total >= ESCALATE_SAMPLE_WINDOW) {
                totalAnalysisCount.set(0);
                escalateCount.set(0);
            }

            if (layer1Assessment != null && layer1Assessment.isShouldEscalate()) {
                int escalates = escalateCount.incrementAndGet();
                double escalateRate = (double) escalates / total;
                if (escalateRate > ESCALATE_RATE_THRESHOLD && total > 10) {
                    log.error("[ColdPath] Escalate rate {}/{} ({}%) exceeded threshold, applying CHALLENGE fallback: eventId={}",
                            escalates, total, String.format("%.1f", escalateRate * 100), event.getEventId());
                    publishEscalateProtectionTriggered(userId, requestPath, escalates, total);
                    result.setFinalScore(null);
                    result.setConfidence(null);
                    result.setAction(ZeroTrustAction.CHALLENGE.name());
                    result.setReasoning("Escalate overload protection - CHALLENGE applied");
                    result.setAnalysisDepth(1);
                    publishDecisionApplied(
                            userId,
                            ZeroTrustAction.CHALLENGE.name(),
                            "ESCALATE_PROTECTION",
                            requestPath,
                            augmentDecisionMetadata(listenerMetadata, result, "ESCALATE_PROTECTION"));
                    return result;
                }
            }

            if (expertStrategy != null) {

                String escalationReason = layer1Assessment != null
                        ? "Layer1 requested expert review based on contextual ambiguity"
                        : "Direct escalation to expert analysis";
                publishLayer2Start(userId, requestPath, escalationReason, listenerMetadata);

                long layer2StartTime = System.currentTimeMillis();
                ThreatAssessment layer2Assessment = expertStrategy.evaluate(event);
                long layer2ElapsedMs = System.currentTimeMillis() - layer2StartTime;

                result.setFinalScore(layer2Assessment.resolveAuditRiskScore());
                result.setConfidence(layer2Assessment.getConfidence());
                result.setLlmAuditConfidence(layer2Assessment.resolveAuditConfidence());
                result.addIndicators(layer2Assessment.getIndicators());
                result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                result.setAnalysisDepth(2);
                result.setProposedAction(layer2Assessment.getAction());
                result.setAction(resolveEnforcedAction(layer2Assessment));
                result.setReasoning(layer2Assessment.getReasoning());
                result.setAutonomyConstraintApplied(layer2Assessment.getAutonomyConstraintApplied());
                result.setAutonomyConstraintReasons(layer2Assessment.getAutonomyConstraintReasons());
                result.setAutonomyConstraintSummary(layer2Assessment.getAutonomyConstraintSummary());
                String layer2Reasoning = layer2Assessment.getReasoning() != null
                        ? layer2Assessment.getReasoning() : "Layer2 expert analysis completed";
                publishLayer2Complete(
                        userId,
                        layer2Assessment.getAction(),
                        layer2Assessment.resolveAuditRiskScore(),
                        layer2Assessment.resolveAuditConfidence(),
                        layer2Reasoning,
                        extractMitre(layer2Assessment),
                        layer2ElapsedMs,
                        augmentAssessmentMetadata(listenerMetadata, layer2Assessment, "LAYER2"));

                publishDecisionApplied(
                        userId,
                        result.getAction(),
                        "LAYER2",
                        requestPath,
                        augmentDecisionMetadata(listenerMetadata, result, "LAYER2"));

                return result;
            }
            return result;

        } catch (Exception e) {
            log.error("[ColdPath] Tiered AI analysis failed, using fallback riskScore: eventId={}", event.getEventId(), e);
            publishError(userId, "Tiered AI analysis failed: " + e.getMessage(), buildErrorMetadata(event));
            result.setFinalScore(null);
            result.setAction(ZeroTrustAction.CHALLENGE.name());
            result.setConfidence(null);
            result.setAnalysisDepth(0);
            return result;
        }
    }

    @Override
    public ProcessingMode getProcessingMode() {
        return ProcessingMode.AI_ANALYSIS;
    }

    @Override
    public String getProcessorName() {
        return "ColdPathEventProcessor-AI";
    }

    @Getter
    @Setter
    public static class ThreatAnalysisResult {
        private double baseScore;
        private Double finalScore;
        private Double confidence;
        private Double llmAuditConfidence;
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;
        private String action;
        private String proposedAction;
        private String reasoning;
        private Boolean autonomyConstraintApplied;
        private List<String> autonomyConstraintReasons = new ArrayList<>();
        private String autonomyConstraintSummary;

        public List<String> getIndicators() {
            return new ArrayList<>(indicators);
        }

        public void addIndicators(List<?> newIndicators) {
            if (newIndicators != null) {
                newIndicators.forEach(i -> this.indicators.add(i.toString()));
            }
        }

        public void addRecommendedActions(List<String> actions) {
            if (actions != null) {
                this.recommendedActions.addAll(actions);
            }
        }

        public SecurityDecision getFinalDecision() {
            ZeroTrustAction proposedDecisionAction;
            ZeroTrustAction enforcedDecisionAction;
            String reasoningPrefix;

            if (proposedAction != null && !proposedAction.isBlank()) {
                reasoningPrefix = "AI Native Decision: ";
                proposedDecisionAction = ZeroTrustAction.fromString(proposedAction);
                enforcedDecisionAction = action != null && !action.isBlank()
                        ? ZeroTrustAction.fromString(action)
                        : proposedDecisionAction;
            } else if (action != null && !action.isBlank()) {
                reasoningPrefix = "AI Native Decision: ";
                proposedDecisionAction = ZeroTrustAction.fromString(action);
                enforcedDecisionAction = proposedDecisionAction;
            } else {
                proposedDecisionAction = ZeroTrustAction.ESCALATE;
                enforcedDecisionAction = ZeroTrustAction.ESCALATE;
                reasoningPrefix = "AI Analysis Incomplete: ";
            }
            return SecurityDecision.builder()
                    .action(proposedDecisionAction)
                    .autonomousAction(enforcedDecisionAction)
                    .riskScore(null)
                    .confidence(confidence)
                    .llmAuditRiskScore(finalScore)
                    .llmAuditConfidence(llmAuditConfidence)
                    .iocIndicators(new ArrayList<>(indicators))
                    .mitigationActions(new ArrayList<>(recommendedActions))
                    .reasoning(reasoningPrefix + (reasoning != null ? reasoning : "No additional reasoning"))
                    .autonomyConstraintApplied(autonomyConstraintApplied)
                    .autonomyConstraintReasons(new ArrayList<>(autonomyConstraintReasons))
                    .autonomyConstraintSummary(autonomyConstraintSummary)
                    .build();
        }
    }

    private String resolveEnforcedAction(ThreatAssessment assessment) {
        if (assessment == null) {
            return ZeroTrustAction.ESCALATE.name();
        }
        if (assessment.getAutonomousAction() != null && !assessment.getAutonomousAction().isBlank()) {
            return assessment.getAutonomousAction();
        }
        if (assessment.getAction() != null && !assessment.getAction().isBlank()) {
            return assessment.getAction();
        }
        return ZeroTrustAction.ESCALATE.name();
    }

    private void publishContextCollected(String userId, String requestPath, String analysisRequirement, Map<String, Object> metadata) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onContextCollected(userId, requestPath, analysisRequirement, metadata);
            } catch (Exception e) {
                log.error("[ColdPath] Failed to publish context collection event: userId={}, requestPath={}", userId, requestPath, e);
            }
        }
    }

    private String extractAnalysisRequirement(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return "PREFERRED";
        }
        Object requirement = event.getMetadata().get("analysisRequirement");
        if (requirement != null) {
            return requirement.toString();
        }
        return "PREFERRED";
    }

    private String extractRequestPath(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return "unknown";
        }
        Object requestPath = event.getMetadata().get("requestPath");
        if (requestPath != null) {
            return requestPath.toString();
        }
        Object fullPath = event.getMetadata().get("fullPath");
        if (fullPath != null) {
            return fullPath.toString();
        }
        return "unknown";
    }

    private String extractMitre(ThreatAssessment assessment) {
        if (assessment == null || assessment.getIndicators() == null) {
            return "none";
        }
        for (Object indicator : assessment.getIndicators()) {
            String str = indicator.toString();
            if (str.startsWith("T") && str.matches("T\\d{4}.*")) {
                return str.split(" ")[0];
            }
        }
        return "none";
    }

    private void publishLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        llmAnalysisEventListener.onLayer1Start(userId, requestPath, metadata);
    }

    private void publishLayer1Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        llmAnalysisEventListener.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
    }

    private void publishLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        llmAnalysisEventListener.onLayer2Start(userId, requestPath, reason, metadata);
    }

    private void publishLayer2Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        llmAnalysisEventListener.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
    }

    private void publishDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        llmAnalysisEventListener.onDecisionApplied(userId, action, layer, requestPath, metadata);
    }

    private void publishError(String userId, String message, Map<String, Object> metadata) {
        llmAnalysisEventListener.onError(userId, message, metadata);
    }

    private void publishEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
        llmAnalysisEventListener.onEscalateProtectionTriggered(userId, requestPath, escalateCount, totalAnalysisCount);
    }

    private Map<String, Object> buildListenerMetadata(SecurityEvent event, String requestPath, String analysisRequirement) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (event != null && event.getMetadata() != null) {
            metadata.putAll(event.getMetadata());
        }
        if (event != null) {
            metadata.put("eventId", event.getEventId());
            metadata.put("userId", event.getUserId());
            metadata.put("sessionId", event.getSessionId());
            metadata.put("clientIp", event.getSourceIp());
            metadata.put("userAgent", event.getUserAgent());
        }
        metadata.put("requestPath", requestPath);
        metadata.put("analysisRequirement", analysisRequirement);
        if (!metadata.containsKey("correlationId") && event != null) {
            metadata.put("correlationId", event.getEventId());
        }
        return Map.copyOf(metadata);
    }

    private Map<String, Object> augmentAssessmentMetadata(
            Map<String, Object> baseMetadata,
            ThreatAssessment assessment,
            String layer) {
        Map<String, Object> metadata = new LinkedHashMap<>(baseMetadata);
        metadata.put("layer", layer);
        if (assessment != null) {
            metadata.put("llmAction", assessment.getAction());
            metadata.put("autonomousAction", assessment.getAutonomousAction());
            metadata.put("riskScore", assessment.resolveAuditRiskScore());
            metadata.put("confidence", assessment.resolveAuditConfidence());
            metadata.put("reasoning", assessment.getReasoning());
            metadata.put("autonomyConstraintApplied", assessment.getAutonomyConstraintApplied());
            metadata.put("autonomyConstraintSummary", assessment.getAutonomyConstraintSummary());
            if (assessment.getAutonomyConstraintReasons() != null && !assessment.getAutonomyConstraintReasons().isEmpty()) {
                metadata.put("autonomyConstraintReasons", assessment.getAutonomyConstraintReasons());
            }
        }
        return Map.copyOf(metadata);
    }

    private Map<String, Object> augmentDecisionMetadata(
            Map<String, Object> baseMetadata,
            ThreatAnalysisResult result,
            String layer) {
        Map<String, Object> metadata = new LinkedHashMap<>(baseMetadata);
        metadata.put("layer", layer);
        metadata.put("action", result.getAction());
        metadata.put("proposedAction", result.getProposedAction());
        metadata.put("riskScore", result.getFinalScore());
        metadata.put("confidence", result.getLlmAuditConfidence());
        metadata.put("reasoning", result.getReasoning());
        metadata.put("analysisDepth", result.getAnalysisDepth());
        metadata.put("autonomyConstraintApplied", result.getAutonomyConstraintApplied());
        metadata.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
        if (result.getAutonomyConstraintReasons() != null && !result.getAutonomyConstraintReasons().isEmpty()) {
            metadata.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
        }
        return Map.copyOf(metadata);
    }

    private Map<String, Object> buildErrorMetadata(SecurityEvent event) {
        String requestPath = extractRequestPath(event);
        String analysisRequirement = extractAnalysisRequirement(event);
        return buildListenerMetadata(event, requestPath, analysisRequirement);
    }
}
