package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacommon.enums.ZeroTrustAction;
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
import java.util.List;
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
            publishContextCollected(userId, requestPath, analysisRequirement);

            ProcessingResult result = ProcessingResult.builder()
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .currentRiskLevel(riskScore)
                    .success(true)
                    .build();
            result.addAnalysisData("analysisRequirement", analysisRequirement);

            ThreatAnalysisResult analysisResult = performTieredAIAnalysis(event, riskScore);
            result.setRiskScore(analysisResult.getFinalScore());
            result.setAction(analysisResult.getAction());
            result.setConfidence(analysisResult.getConfidence());
            result.setReasoning(analysisResult.getReasoning());
            result.setThreatIndicators(analysisResult.getIndicators());
            result.setRecommendedActions(new ArrayList<>(analysisResult.getRecommendedActions()));
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());
            result.addAnalysisData("aiAssessment", analysisResult);

            long processingTime = System.currentTimeMillis() - startTime;
            result.setProcessingTimeMs(processingTime);
            result.setProcessedAt(LocalDateTime.now());
            result.setStatus(ProcessingResult.ProcessingStatus.SUCCESS);

            return result;

        } catch (Exception e) {
            log.error("[ColdPath] Processing failed: eventId={}", event.getEventId(), e);
            return ProcessingResult.failure(
                    ProcessingResult.ProcessingPath.COLD_PATH,
                    "AI analysis failed: " + e.getMessage()
            );
        }
    }

    private ThreatAnalysisResult performTieredAIAnalysis(SecurityEvent event, double riskScore) {
        ThreatAnalysisResult result = new ThreatAnalysisResult();
        result.setBaseScore(riskScore);
        String userId = event.getUserId();
        String requestPath = extractRequestPath(event);

        try {
            ThreatAssessment layer1Assessment = null;
            if (contextualStrategy != null) {
                publishLayer1Start(userId, requestPath);
                long layer1StartTime = System.currentTimeMillis();
                layer1Assessment = contextualStrategy.evaluate(event);
                long layer1ElapsedMs = System.currentTimeMillis() - layer1StartTime;

                if (!layer1Assessment.isShouldEscalate()) {
                    result.setFinalScore(layer1Assessment.getRiskScore());
                    result.setConfidence(layer1Assessment.getConfidence());
                    result.addIndicators(layer1Assessment.getIndicators());
                    result.addRecommendedActions(layer1Assessment.getRecommendedActions());
                    result.setAnalysisDepth(1);
                    result.setAction(layer1Assessment.getAction());
                    result.setReasoning(layer1Assessment.getReasoning());
                    String reasoning = layer1Assessment.getReasoning() != null
                            ? layer1Assessment.getReasoning() : "Layer1 analysis completed";
                    publishLayer1Complete(userId, layer1Assessment.getAction(),
                            layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                            reasoning, extractMitre(layer1Assessment), layer1ElapsedMs);

                    publishDecisionApplied(userId, layer1Assessment.getAction(), "LAYER1", requestPath);

                    return result;
                }

                publishLayer1Complete(userId, ZeroTrustAction.ESCALATE.name(),
                        layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                        "Escalating to Layer2 for deeper analysis", "none", layer1ElapsedMs);

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
                    result.setFinalScore(0.5);
                    result.setConfidence(0.4);
                    result.setAction(ZeroTrustAction.CHALLENGE.name());
                    result.setReasoning("Escalate overload protection - CHALLENGE applied");
                    result.setAnalysisDepth(1);
                    publishDecisionApplied(userId, ZeroTrustAction.CHALLENGE.name(), "ESCALATE_PROTECTION", requestPath);
                    return result;
                }
            }

            if (expertStrategy != null) {

                String escalationReason = layer1Assessment != null
                        ? "Low confidence in Layer1: " + layer1Assessment.getConfidence()
                        : "Direct escalation to expert analysis";
                publishLayer2Start(userId, requestPath, escalationReason);

                long layer2StartTime = System.currentTimeMillis();
                ThreatAssessment layer2Assessment = expertStrategy.evaluate(event);
                long layer2ElapsedMs = System.currentTimeMillis() - layer2StartTime;

                result.setFinalScore(layer2Assessment.getRiskScore());
                result.setConfidence(layer2Assessment.getConfidence());
                result.addIndicators(layer2Assessment.getIndicators());
                result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                result.setAnalysisDepth(2);
                result.setAction(layer2Assessment.getAction());
                result.setReasoning(layer2Assessment.getReasoning());
                String layer2Reasoning = layer2Assessment.getReasoning() != null
                        ? layer2Assessment.getReasoning() : "Layer2 expert analysis completed";
                publishLayer2Complete(userId, layer2Assessment.getAction(),
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Reasoning, extractMitre(layer2Assessment), layer2ElapsedMs);

                publishDecisionApplied(userId, layer2Assessment.getAction(), "LAYER2", requestPath);

                return result;
            }
            return result;

        } catch (Exception e) {
            log.error("[ColdPath] Tiered AI analysis failed, using fallback riskScore: eventId={}", event.getEventId(), e);
            result.setFinalScore(riskScore);
            result.setAction(ZeroTrustAction.CHALLENGE.name());
            result.setConfidence(0.3);
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
        private double finalScore;
        private double confidence;
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;
        private String action;
        private String reasoning;

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
            ZeroTrustAction decisionAction;
            String reasoningPrefix;

            if (action != null && !action.isBlank()) {
                reasoningPrefix = "AI Native Decision: ";
                decisionAction = ZeroTrustAction.fromString(action);
            } else {
                decisionAction = ZeroTrustAction.ESCALATE;
                reasoningPrefix = "AI Analysis Incomplete: ";
            }
            return SecurityDecision.builder()
                    .action(decisionAction)
                    .riskScore(finalScore)
                    .confidence(confidence)
                    .iocIndicators(new ArrayList<>(indicators))
                    .mitigationActions(new ArrayList<>(recommendedActions))
                    .reasoning(reasoningPrefix)
                    .build();
        }
    }

    private void publishContextCollected(String userId, String requestPath, String analysisRequirement) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onContextCollected(userId, requestPath, analysisRequirement);
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

    private void publishLayer1Start(String userId, String requestPath) {
        llmAnalysisEventListener.onLayer1Start(userId, requestPath);
    }

    private void publishLayer1Complete(String userId, String action, Double riskScore,
                                       Double confidence, String reasoning, String mitre, Long elapsedMs) {
        llmAnalysisEventListener.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    private void publishLayer2Start(String userId, String requestPath, String reason) {
        llmAnalysisEventListener.onLayer2Start(userId, requestPath, reason);
    }

    private void publishLayer2Complete(String userId, String action, Double riskScore,
                                       Double confidence, String reasoning, String mitre, Long elapsedMs) {
        llmAnalysisEventListener.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
    }

    private void publishDecisionApplied(String userId, String action, String layer, String requestPath) {
        llmAnalysisEventListener.onDecisionApplied(userId, action, layer, requestPath);
    }
}
