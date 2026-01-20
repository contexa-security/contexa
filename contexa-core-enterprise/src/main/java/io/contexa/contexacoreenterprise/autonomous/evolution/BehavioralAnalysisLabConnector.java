package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.labs.behavior.BehavioralAnalysisLab;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;


@Slf4j
@RequiredArgsConstructor
public class BehavioralAnalysisLabConnector {

    @Autowired(required = false)
    private BehavioralAnalysisLab behavioralAnalysisLab;

    @Autowired(required = false)
    private BehaviorVectorService behaviorVectorService;

    @Value("${behavioral.analysis.enabled:true}")
    private boolean enabled;

    @Value("${behavioral.analysis.timeout.ms:1000}")
    private long analysisTimeoutMs;

    @Value("${behavioral.analysis.min.confidence:0.6}")
    private double minConfidenceThreshold;

    @Value("${behavioral.analysis.vector.similarity.threshold:0.85}")
    private double vectorSimilarityThreshold;

    
    public boolean isEnabled() {
        return enabled && behavioralAnalysisLab != null;
    }

    
    public ThreatAssessment analyzeBehavior(SecurityEvent event) {
        if (!isEnabled()) {
            log.warn("[BehavioralConnector] 행동 분석 랩이 비활성화됨");
            return createDisabledAssessment(event);
        }

        String analysisId = UUID.randomUUID().toString();
        log.info("[BehavioralConnector] 행동 분석 시작 - ID: {}, Event: {}, User: {}",
            analysisId, event.getEventId(), event.getUserId());

        try {
            
            BehavioralAnalysisContext context = createContext(event);

            
            BehavioralAnalysisRequest request = createRequest(context, event);

            
            CompletableFuture<BehavioralAnalysisResponse> future = executeBehavioralAnalysis(request);

            
            BehavioralAnalysisResponse response = future.get(analysisTimeoutMs, TimeUnit.MILLISECONDS);

            
            ThreatAssessment assessment = convertToThreatAssessment(response, event, analysisId);

            
            if (behaviorVectorService != null) {
                enrichWithVectorAnalysis(assessment, event);
            }

            log.info("[BehavioralConnector] 행동 분석 완료 - ID: {}, RiskScore: {}, Confidence: {}",
                analysisId, assessment.getRiskScore(), assessment.getConfidence());

            return assessment;

        } catch (Exception e) {
            log.error("[BehavioralConnector] 행동 분석 실패 - ID: {}", analysisId, e);
            return createErrorAssessment(event, analysisId, e.getMessage());
        }
    }

    
    private BehavioralAnalysisContext createContext(SecurityEvent event) {
        BehavioralAnalysisContext context = new BehavioralAnalysisContext();

        
        context.setUserId(event.getUserId());
        context.setRemoteIp(event.getSourceIp());

        
        String currentActivity = String.format("%s from %s (Session: %s)",
            event.getSeverity() != null ? event.getSeverity().toString() : "UNKNOWN",
            event.getSourceIp() != null ? event.getSourceIp() : "unknown",
            event.getSessionId() != null ? event.getSessionId() : "none");
        context.setCurrentActivity(currentActivity);

        
        StringBuilder historicalSummary = new StringBuilder();
        historicalSummary.append("Severity: ").append(event.getSeverity());
        if (event.getUserAgent() != null) {
            historicalSummary.append(", UserAgent: ").append(event.getUserAgent());
        }
        
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("targetResource")) {
            historicalSummary.append(", Resource: ").append(metadata.get("targetResource"));
        }
        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            historicalSummary.append(", Metadata: ").append(event.getMetadata().toString());
        }

        context.setHistoricalBehaviorSummary(historicalSummary.toString());

        return context;
    }

    
    private BehavioralAnalysisRequest createRequest(BehavioralAnalysisContext context, SecurityEvent event) {
        
        String operation = String.format("analyze_%s", event.getSeverity().toString().toLowerCase());
        BehavioralAnalysisRequest request = BehavioralAnalysisRequest.create(context, operation, event.getSessionId());

        return request;
    }

    
    private CompletableFuture<BehavioralAnalysisResponse> executeBehavioralAnalysis(BehavioralAnalysisRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                
                Mono<BehavioralAnalysisResponse> mono = behavioralAnalysisLab.processAsync(request);
                return mono.block();
            } catch (Exception e) {
                log.error("[BehavioralConnector] 랩 실행 오류", e);
                throw new RuntimeException("행동 분석 랩 실행 실패", e);
            }
        });
    }

    
    private ThreatAssessment convertToThreatAssessment(
            BehavioralAnalysisResponse response, SecurityEvent event, String assessmentId) {

        
        double riskScore = calculateRiskScore(response);

        
        double confidence = calculateConfidence(response);

        
        

        
        List<String> recommendedActions = extractRecommendedActions(response, riskScore);

        
        Map<String, Object> details = new HashMap<>();
        details.put("behavioralRiskScore", response.getBehavioralRiskScore());
        details.put("riskLevel", response.getRiskLevel());
        details.put("summary", response.getSummary());
        details.put("anomalies", response.getAnomalies());
        details.put("analysisId", response.getAnalysisId());
        details.put("confidence", confidence);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(assessmentId)
            .assessedAt(LocalDateTime.now())
            .evaluator("BehavioralAnalysisLab")
            .riskScore(riskScore)
            .confidence(confidence)
            .recommendedActions(recommendedActions)
            
            .build();
    }

    
    private double calculateRiskScore(BehavioralAnalysisResponse response) {
        double baseScore = 0.0;

        
        baseScore = response.getBehavioralRiskScore() / 100.0;

        
        if (response.getRiskLevel() != null) {
            switch (response.getRiskLevel()) {
                case CRITICAL:
                    baseScore = Math.max(baseScore, 0.9);
                    break;
                case HIGH:
                    baseScore = Math.max(baseScore, 0.7);
                    break;
                case MEDIUM:
                    baseScore = Math.max(baseScore, 0.5);
                    break;
                case LOW:
                    baseScore = Math.max(baseScore, 0.3);
                    break;
            }
        }

        
        if (response.getAnomalies() != null && !response.getAnomalies().isEmpty()) {
            double anomalyBonus = Math.min(response.getAnomalies().size() * 0.1, 0.3);
            baseScore += anomalyBonus;
        }

        return Math.min(baseScore, 1.0);
    }

    
    private double calculateConfidence(BehavioralAnalysisResponse response) {
        double confidence = 0.7; 

        
        if (response.getAnomalies() != null && response.getAnomalies().size() > 0) {
            confidence += 0.1; 
        }

        if (response.getRecommendations() != null && response.getRecommendations().size() > 0) {
            confidence += 0.1; 
        }

        if (response.getSummary() != null && !response.getSummary().trim().isEmpty()) {
            confidence += 0.1; 
        }

        
        if (confidence < minConfidenceThreshold) {
            confidence = minConfidenceThreshold;
        }

        return Math.min(confidence, 1.0);
    }

    
    
    
    

    
    private List<String> extractRecommendedActions(BehavioralAnalysisResponse response, double riskScore) {
        List<String> actions = new ArrayList<>();

        
        if (response.getRecommendations() != null) {
            response.getRecommendations().forEach(rec -> {
                if (rec.getAction() != null) {
                    actions.add(rec.getAction());
                }
            });
        }

        
        if (riskScore >= 0.9) {
            actions.add("immediate_block");
            actions.add("alert_security_team");
            actions.add("forensic_analysis");
        } else if (riskScore >= 0.7) {
            actions.add("enhanced_monitoring");
            actions.add("require_mfa");
            actions.add("limit_access");
        } else if (riskScore >= 0.5) {
            actions.add("monitor");
            actions.add("log_activity");
            actions.add("review_permissions");
        } else {
            actions.add("continue_monitoring");
            actions.add("update_baseline");
        }

        return actions.stream().distinct().toList();
    }

    
    private void enrichWithVectorAnalysis(ThreatAssessment assessment, SecurityEvent event) {
        try {
            String userId = event.getUserId();
            
            
            
            String sourceIp = event.getSourceIp();
            String requestPath = event.getMetadata() != null ?
                    (String) event.getMetadata().get("requestUri") : null;

            
            List<org.springframework.ai.document.Document> similarBehaviors =
                behaviorVectorService.findSimilarBehaviors(userId, sourceIp, requestPath, 10);

            
            Map<String, Object> vectorAnalysis = analyzeSimilarBehaviors(similarBehaviors, event);

            
            

            
            if (vectorAnalysis.containsKey("anomalyScoreAdjustment")) {
                double adjustment = (Double) vectorAnalysis.get("anomalyScoreAdjustment");
                double currentRiskScore = assessment.getRiskScore();
                double adjustedRiskScore = Math.min(Math.max(currentRiskScore + adjustment, 0.0), 1.0);

                assessment.setRiskScore(adjustedRiskScore);

                log.debug("[BehavioralConnector] 벡터 분석 기반 위험 점수 조정: {} → {}",
                    currentRiskScore, adjustedRiskScore);
            }

            
            if (vectorAnalysis.containsKey("additionalActions")) {
                @SuppressWarnings("unchecked")
                List<String> additionalActions = (List<String>) vectorAnalysis.get("additionalActions");
                List<String> currentActions = new ArrayList<>(assessment.getRecommendedActions());
                currentActions.addAll(additionalActions);
                assessment.setRecommendedActions(currentActions.stream().distinct().toList());
            }

            log.debug("[BehavioralConnector] 벡터 분석 완료: 유사 패턴 {}개 발견, 이상 점수 조정 여부: {}",
                similarBehaviors.size(), vectorAnalysis.containsKey("anomalyScoreAdjustment"));

        } catch (Exception e) {
            log.warn("[BehavioralConnector] 벡터 분석 실패 (무시하고 계속 진행)", e);
            
        }
    }

    
    private Map<String, Object> analyzeSimilarBehaviors(
            List<org.springframework.ai.document.Document> similarBehaviors, SecurityEvent event) {

        Map<String, Object> analysis = new HashMap<>();

        if (similarBehaviors.isEmpty()) {
            
            analysis.put("anomalyScoreAdjustment", 0.3); 
            analysis.put("pattern", "NO_SIMILAR_PATTERN");
            analysis.put("additionalActions", List.of("detailed_investigation", "behavior_baseline_update"));
            return analysis;
        }

        
        double avgSimilarity = similarBehaviors.stream()
            .mapToDouble(doc -> {
                Object simScore = doc.getMetadata().get("similarity_score");
                if (simScore instanceof Number) {
                    return ((Number) simScore).doubleValue();
                }
                return 0.0;
            })
            .average()
            .orElse(0.0);

        analysis.put("averageSimilarity", avgSimilarity);

        
        List<Map<String, Object>> historicalPatterns = new ArrayList<>();
        for (org.springframework.ai.document.Document doc : similarBehaviors) {
            Map<String, Object> pattern = new HashMap<>();
            pattern.put("activity", doc.getMetadata().get("currentActivity"));
            pattern.put("riskScore", doc.getMetadata().get("riskScore"));
            pattern.put("timestamp", doc.getMetadata().get("timestamp"));
            pattern.put("outcome", doc.getMetadata().get("outcome"));
            historicalPatterns.add(pattern);
        }
        analysis.put("historicalPatterns", historicalPatterns);

        
        long riskBehaviorCount = similarBehaviors.stream()
            .filter(doc -> {
                Object riskScore = doc.getMetadata().get("riskScore");
                if (riskScore instanceof Number) {
                    return ((Number) riskScore).doubleValue() >= 60.0;
                }
                return false;
            })
            .count();

        double riskBehaviorRatio = similarBehaviors.isEmpty() ? 0.0 :
            (double) riskBehaviorCount / similarBehaviors.size();
        analysis.put("riskBehaviorRatio", riskBehaviorRatio);

        
        if (avgSimilarity < vectorSimilarityThreshold) {
            
            double adjustment = (vectorSimilarityThreshold - avgSimilarity) * 0.3;
            analysis.put("anomalyScoreAdjustment", adjustment);
        } else if (riskBehaviorRatio > 0.5) {
            
            analysis.put("anomalyScoreAdjustment", riskBehaviorRatio * 0.2);
        }

        
        List<String> additionalActions = new ArrayList<>();
        if (avgSimilarity < 0.5) {
            additionalActions.add("verify_user_identity");
            additionalActions.add("check_account_compromise");
        }
        if (riskBehaviorRatio > 0.7) {
            additionalActions.add("review_user_permissions");
            additionalActions.add("strengthen_monitoring");
        }
        if (!additionalActions.isEmpty()) {
            analysis.put("additionalActions", additionalActions);
        }

        
        if (avgSimilarity >= vectorSimilarityThreshold && riskBehaviorRatio < 0.3) {
            analysis.put("pattern", "NORMAL_BEHAVIOR");
        } else if (avgSimilarity >= 0.7 && riskBehaviorRatio >= 0.5) {
            analysis.put("pattern", "RISKY_BEHAVIOR_PATTERN");
        } else if (avgSimilarity < 0.5) {
            analysis.put("pattern", "ANOMALOUS_BEHAVIOR");
        } else {
            analysis.put("pattern", "SUSPICIOUS_BEHAVIOR");
        }

        return analysis;
    }

    
    private ThreatAssessment createDisabledAssessment(SecurityEvent event) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator("BehavioralAnalysisLab-Disabled")
            .riskScore(0.5)
            .confidence(0.0)
            .recommendedActions(List.of("enable_behavioral_analysis"))
            
            .build();
    }

    
    private ThreatAssessment createErrorAssessment(SecurityEvent event, String assessmentId, String error) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(assessmentId)
            .assessedAt(LocalDateTime.now())
            .evaluator("BehavioralAnalysisLab-Error")
            .riskScore(0.5)
            .confidence(0.3)
            .recommendedActions(List.of("manual_review", "fallback_analysis"))
            
            .description("Error: " + error)
            .build();
    }
}