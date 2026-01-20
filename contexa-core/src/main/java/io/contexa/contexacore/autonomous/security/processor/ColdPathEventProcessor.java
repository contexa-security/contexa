package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
@RequiredArgsConstructor
public class ColdPathEventProcessor implements IPathProcessor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Layer1ContextualStrategy contextualStrategy;
    private final Layer2ExpertStrategy expertStrategy;

    
    @Autowired(required = false)
    private BaselineLearningService baselineLearningService;

    
    @Autowired(required = false)
    private AdminOverrideService adminOverrideService;

    
    @Autowired(required = false)
    private LlmAnalysisEventListener llmAnalysisEventListener;

    private final AtomicLong processedCount = new AtomicLong(0);
    private final AtomicLong totalProcessingTime = new AtomicLong(0);
    private volatile long lastProcessedTimestamp = 0;

    
    
    
    

    
    @Override
    public ProcessingResult processEvent(SecurityEvent event, double riskScore) {
        long startTime = System.currentTimeMillis();

        try {
            String userId = event.getUserId();
            if (userId == null) {
                log.warn("Cold Path: userId가 없는 이벤트 - eventId: {}", event.getEventId());
                return ProcessingResult.failure(
                    ProcessingResult.ProcessingPath.COLD_PATH,
                    "Missing userId"
                );
            }

            log.info("Cold Path 계층적 AI 진단 시작 - userId: {}, eventId: {}, riskScore: {}",
                    userId, event.getEventId(), riskScore);

            
            String requestPath = extractRequestPath(event);
            String analysisRequirement = extractAnalysisRequirement(event);
            publishContextCollected(userId, requestPath, analysisRequirement);
            
            
            ProcessingResult result = ProcessingResult.builder()
                    .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                    .currentRiskLevel(riskScore)
                    .aiAnalysisPerformed(true)
                    .success(true)
                    .build();

            
            ThreatAnalysisResult analysisResult = performTieredAIAnalysis(event, riskScore);

            
            result.setRiskScore(analysisResult.getFinalScore());

            result.addAnalysisData("aiAssessment", analysisResult);
            
            result.addAnalysisData("action", analysisResult.getAction());

            
            result.setAiAnalysisLevel(analysisResult.getAnalysisDepth());

            
            final String finalUserId = userId;
            final SecurityEvent finalEvent = event;
            final ThreatAnalysisResult finalAnalysisResult = analysisResult;

            
            
            try {
                saveAnalysisToRedis(finalUserId, finalAnalysisResult);
            } catch (Exception ex) {
                log.error("[ColdPath][CRITICAL] Redis 분석 결과 저장 실패 (동기): userId={}, eventId={}",
                    userId, event.getEventId(), ex);
                
            }

            
            
            
            CompletableFuture.runAsync(() -> {
                learnFromAnalysisResult(finalUserId, finalEvent, finalAnalysisResult);
            }).exceptionally(ex -> {
                log.error("[ColdPath] Baseline 학습 실패 (비-치명적): userId={}", finalUserId, ex);
                return null;
            });
            
            
            long processingTime = System.currentTimeMillis() - startTime;
            updateStatistics(processingTime);
            
            
            result.setProcessingTimeMs(processingTime);
            result.setProcessedAt(LocalDateTime.now());
            result.setStatus(ProcessingResult.ProcessingStatus.SUCCESS);
            
            log.info("Cold Path AI 진단 완료 - userId: {}, finalScore: {}, action: {}, 시간: {}ms",
                    userId, analysisResult.getFinalScore(), analysisResult.getAction(), processingTime);
            
            return result;
            
        } catch (Exception e) {
            log.error("Cold Path 처리 실패 - eventId: {}", event.getEventId(), e);
            return ProcessingResult.failure(
                ProcessingResult.ProcessingPath.COLD_PATH,
                "AI analysis failed: " + e.getMessage()
            );
        }
    }


    
    private ThreatAnalysisResult performTieredAIAnalysis(SecurityEvent event, double riskScore) {
        ThreatAnalysisResult result = new ThreatAnalysisResult();
        result.setBaseScore(riskScore);

        long startTime = System.currentTimeMillis();
        String userId = event.getUserId();
        String requestPath = extractRequestPath(event);

        try {
            
            log.info("계층적 분석 시작 - riskScore: {}, eventId: {}",
                    riskScore, event.getEventId());

            ThreatAssessment layer1Assessment = null;
            if (contextualStrategy != null) {
                log.debug("Layer 1 컨텍스트 분석 시작 - eventId: {}", event.getEventId());

                
                publishLayer1Start(userId, requestPath);

                long layer1StartTime = System.currentTimeMillis();
                layer1Assessment = contextualStrategy.evaluate(event);
                long layer1ElapsedMs = System.currentTimeMillis() - layer1StartTime;

                
                log.info("Layer 1 평가: riskScore={}, confidence={}, action={}, shouldEscalate={}",
                        layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                        layer1Assessment.getAction(), layer1Assessment.isShouldEscalate());

                
                
                if (!layer1Assessment.isShouldEscalate()) {
                    result.setFinalScore(layer1Assessment.getRiskScore());
                    result.setConfidence(layer1Assessment.getConfidence());
                    result.addIndicators(layer1Assessment.getIndicators());
                    result.addRecommendedActions(layer1Assessment.getRecommendedActions());
                    result.setAnalysisDepth(1); 
                    result.setAction(layer1Assessment.getAction()); 

                    
                    
                    String reasoning = layer1Assessment.getReasoning() != null
                            ? layer1Assessment.getReasoning() : "Layer1 analysis completed";
                    publishLayer1Complete(userId, layer1Assessment.getAction(),
                            layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                            reasoning, extractMitre(layer1Assessment), layer1ElapsedMs);

                    
                    publishDecisionApplied(userId, layer1Assessment.getAction(), "LAYER1", requestPath);

                    log.info("Layer 1에서 처리 완료 - LLM이 에스컬레이션 불필요 판단, action: {}, 시간: {}ms",
                            layer1Assessment.getAction(), System.currentTimeMillis() - startTime);

                    return result;
                }

                
                publishLayer1Complete(userId, "ESCALATE",
                        layer1Assessment.getRiskScore(), layer1Assessment.getConfidence(),
                        "Escalating to Layer2 for deeper analysis", "none", layer1ElapsedMs);

                
                event.getMetadata().put("layer1Assessment", layer1Assessment);
                log.debug("Layer 1 결과를 metadata에 저장 - Layer2로 전달");
            }

            
            if (expertStrategy != null) {
                log.debug("Layer 2 전문가 분석 시작 - eventId: {}", event.getEventId());

                
                String escalationReason = layer1Assessment != null
                        ? "Low confidence in Layer1: " + layer1Assessment.getConfidence()
                        : "Direct escalation to expert analysis";
                publishLayer2Start(userId, requestPath, escalationReason);

                long layer2StartTime = System.currentTimeMillis();
                ThreatAssessment layer2Assessment = expertStrategy.evaluate(event);
                long layer2ElapsedMs = System.currentTimeMillis() - layer2StartTime;

                
                log.info("Layer 2 평가: riskScore={}, confidence={}, action={}",
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Assessment.getAction());

                result.setFinalScore(layer2Assessment.getRiskScore());
                result.setConfidence(layer2Assessment.getConfidence());
                result.addIndicators(layer2Assessment.getIndicators());
                result.addRecommendedActions(layer2Assessment.getRecommendedActions());
                result.setAnalysisDepth(2); 
                result.setAction(layer2Assessment.getAction()); 

                
                
                String layer2Reasoning = layer2Assessment.getReasoning() != null
                        ? layer2Assessment.getReasoning() : "Layer2 expert analysis completed";
                publishLayer2Complete(userId, layer2Assessment.getAction(),
                        layer2Assessment.getRiskScore(), layer2Assessment.getConfidence(),
                        layer2Reasoning, extractMitre(layer2Assessment), layer2ElapsedMs);

                
                publishDecisionApplied(userId, layer2Assessment.getAction(), "LAYER2", requestPath);

                log.info("Layer 2에서 최종 처리 완료 (5% 케이스) - action: {}, 시간: {}ms",
                        layer2Assessment.getAction(), System.currentTimeMillis() - startTime);

                return result;
            }
            return result;

        } catch (Exception e) {
            log.error("계층적 AI 분석 실패 - eventId: {}, riskScore를 fallback으로 사용", event.getEventId(), e);
            
            
            result.setFinalScore(riskScore);

            
            result.setAction("ESCALATE");

            
            result.setConfidence(Double.NaN);
            result.setAnalysisDepth(0);  
            return result;
        }
    }

    
    private synchronized void updateStatistics(long processingTime) {
        processedCount.incrementAndGet();
        totalProcessingTime.addAndGet(processingTime);
        lastProcessedTimestamp = System.currentTimeMillis();
    }

    
    private void saveAnalysisToRedis(String userId, ThreatAnalysisResult analysisResult) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            
            String action = analysisResult.getAction();
            if (action == null || action.isBlank()) {
                
                action = "ESCALATE";
                log.warn("[ColdPath][AI Native] LLM action 미반환, ESCALATE 설정 - userId: {}", userId);
            }

            
            
            
            
            
            Duration ttl = switch (action.toUpperCase()) {
                case "BLOCK" -> null;  
                case "ESCALATE" -> Duration.ofMinutes(5);
                case "CHALLENGE" -> Duration.ofMinutes(30);
                default -> Duration.ofSeconds(30);  
            };

            
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<String, Object> fields = new HashMap<>();
            fields.put("action", action);
            fields.put("riskScore", analysisResult.getFinalScore());
            fields.put("confidence", analysisResult.getConfidence());
            fields.put("threatEvidence", String.join(", ", analysisResult.getIndicators()));
            fields.put("analysisDepth", analysisResult.getAnalysisDepth());
            fields.put("updatedAt", java.time.Instant.now().toString());

            redisTemplate.opsForHash().putAll(analysisKey, fields);
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            log.info("[ColdPath][AI Native] Analysis saved to Redis: userId={}, action={}, riskScore={}, confidence={}, ttl={}",
                    userId, action,
                    String.format("%.3f", analysisResult.getFinalScore()),
                    String.format("%.3f", analysisResult.getConfidence()),
                    ttl != null ? ttl.toSeconds() + "s" : "permanent");

            
            if ("BLOCK".equalsIgnoreCase(action) && adminOverrideService != null) {
                String requestId = (String) fields.get("requestId");
                if (requestId == null) {
                    requestId = UUID.randomUUID().toString();
                }
                String reasoning = String.join(", ", analysisResult.getIndicators());

                adminOverrideService.addToPendingReview(
                    requestId,
                    userId,
                    analysisResult.getFinalScore(),
                    analysisResult.getConfidence(),
                    reasoning
                );

                log.info("[ColdPath][AI Native] BLOCK 요청을 관리자 검토 대기열에 추가: userId={}, requestId={}",
                    userId, requestId);
            }

        } catch (Exception e) {
            log.error("[ColdPath] Failed to save analysis to Redis: userId={}", userId, e);
        }
    }

    
    private void learnFromAnalysisResult(String userId, SecurityEvent event, ThreatAnalysisResult analysisResult) {
        if (baselineLearningService == null) {
            log.debug("[ColdPath] BaselineLearningService not available, skipping baseline learning");
            return;
        }

        if (userId == null || userId.isBlank() || analysisResult == null) {
            return;
        }

        try {
            
            SecurityDecision decision = analysisResult.getFinalDecision();

            
            
            boolean learned = baselineLearningService.learnIfNormal(userId, decision, event);

            if (learned) {
                log.debug("[ColdPath][AI Native] Baseline learning completed: userId={}, action={}, confidence={}",
                    userId, decision.getAction(), String.format("%.3f", decision.getConfidence()));
            }

        } catch (Exception e) {
            log.warn("[ColdPath] Baseline learning failed (non-critical): userId={}", userId, e);
            
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
    
    
    
    

    
    
    
    

    @Override
    public ProcessorStatistics getStatistics() {
        ProcessorStatistics stats = new ProcessorStatistics();
        stats.setProcessedCount(processedCount.get());
        
        long count = processedCount.get();
        if (count > 0) {
            stats.setAverageProcessingTime((double) totalProcessingTime.get() / count);
        }
        
        stats.setLastProcessedTimestamp(lastProcessedTimestamp);
        
        return stats;
    }
    
    
    @Getter @Setter
    public static class ThreatAnalysisResult {
        private double baseScore;
        private double finalScore;
        private double confidence;
        private Set<String> indicators = new HashSet<>();
        private Set<String> recommendedActions = new HashSet<>();
        private int analysisDepth = 0;
        
        
        private String action;

        public List<String> getIndicators() { return new ArrayList<>(indicators); }

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
            
            SecurityDecision.Action decisionAction;
            String reasoningPrefix;

            if (action != null && !action.isBlank()) {
                
                reasoningPrefix = "AI Native Decision: ";
                decisionAction = switch (action.toUpperCase()) {
                    case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
                    case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
                    case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
                    default -> SecurityDecision.Action.ESCALATE;  
                };
            } else {
                
                decisionAction = SecurityDecision.Action.ESCALATE;
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
                log.debug("[ColdPath][SSE] 컨텍스트 수집 이벤트 발행 실패: {}", e.getMessage());
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
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onLayer1Start(userId, requestPath);
            } catch (Exception e) {
                log.debug("[ColdPath][SSE] Layer1 시작 이벤트 발행 실패: {}", e.getMessage());
            }
        }
    }

    private void publishLayer1Complete(String userId, String action, Double riskScore,
            Double confidence, String reasoning, String mitre, Long elapsedMs) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onLayer1Complete(userId, action, riskScore,
                        confidence, reasoning, mitre, elapsedMs);
            } catch (Exception e) {
                log.debug("[ColdPath][SSE] Layer1 완료 이벤트 발행 실패: {}", e.getMessage());
            }
        }
    }

    private void publishLayer2Start(String userId, String requestPath, String reason) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onLayer2Start(userId, requestPath, reason);
            } catch (Exception e) {
                log.debug("[ColdPath][SSE] Layer2 시작 이벤트 발행 실패: {}", e.getMessage());
            }
        }
    }

    private void publishLayer2Complete(String userId, String action, Double riskScore,
            Double confidence, String reasoning, String mitre, Long elapsedMs) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onLayer2Complete(userId, action, riskScore,
                        confidence, reasoning, mitre, elapsedMs);
            } catch (Exception e) {
                log.debug("[ColdPath][SSE] Layer2 완료 이벤트 발행 실패: {}", e.getMessage());
            }
        }
    }

    private void publishDecisionApplied(String userId, String action, String layer, String requestPath) {
        if (llmAnalysisEventListener != null) {
            try {
                llmAnalysisEventListener.onDecisionApplied(userId, action, layer, requestPath);
            } catch (Exception e) {
                log.debug("[ColdPath][SSE] 최종 결정 이벤트 발행 실패: {}", e.getMessage());
            }
        }
    }
}