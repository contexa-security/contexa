package io.contexa.contexacore.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.std.labs.behavior.BehavioralAnalysisLab;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * BehavioralAnalysisLabConnector - 행동 분석 랩 연결자
 *
 * autonomous 패키지와 std.labs.behavior 패키지를 연결하여
 * BehavioralAnalysisLab의 고급 행동 분석 기능을 활용합니다.
 *
 * @since 1.0
 */
@Slf4j
@Component
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

    /**
     * 행동 분석 랩 활성화 여부
     */
    public boolean isEnabled() {
        return enabled && behavioralAnalysisLab != null;
    }

    /**
     * SecurityEvent를 분석하여 ThreatAssessment 생성
     *
     * @param event 보안 이벤트
     * @return 위협 평가 결과
     */
    public ThreatAssessment analyzeBehavior(SecurityEvent event) {
        if (!isEnabled()) {
            log.warn("[BehavioralConnector] 행동 분석 랩이 비활성화됨");
            return createDisabledAssessment(event);
        }

        String analysisId = UUID.randomUUID().toString();
        log.info("[BehavioralConnector] 행동 분석 시작 - ID: {}, Event: {}, User: {}",
            analysisId, event.getEventId(), event.getUserId());

        try {
            // 1. BehavioralAnalysisContext 생성
            BehavioralAnalysisContext context = createContext(event);

            // 2. BehavioralAnalysisRequest 생성
            BehavioralAnalysisRequest request = createRequest(context, event);

            // 3. 비동기 분석 실행
            CompletableFuture<BehavioralAnalysisResponse> future = executeBehavioralAnalysis(request);

            // 4. 타임아웃 적용하여 결과 대기
            BehavioralAnalysisResponse response = future.get(analysisTimeoutMs, TimeUnit.MILLISECONDS);

            // 5. 응답을 ThreatAssessment로 변환
            ThreatAssessment assessment = convertToThreatAssessment(response, event, analysisId);

            // 6. 벡터 유사도 분석 (있는 경우)
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

    /**
     * SecurityEvent로부터 BehavioralAnalysisContext 생성
     */
    private BehavioralAnalysisContext createContext(SecurityEvent event) {
        BehavioralAnalysisContext context = new BehavioralAnalysisContext();

        // 필수 정보 설정 (실제 존재하는 필드만)
        context.setUserId(event.getUserId());
        context.setRemoteIp(event.getSourceIp());

        // 현재 활동 설정
        String currentActivity = String.format("%s from %s (Session: %s)",
            event.getEventType().getDisplayName(),
            event.getSourceIp() != null ? event.getSourceIp() : "unknown",
            event.getSessionId() != null ? event.getSessionId() : "none");
        context.setCurrentActivity(currentActivity);

        // 과거 행동 데이터 요약 (메타데이터에서 추출)
        StringBuilder historicalSummary = new StringBuilder();
        historicalSummary.append("Event: ").append(event.getEventType().getDisplayName());
        if (event.getUserAgent() != null) {
            historicalSummary.append(", UserAgent: ").append(event.getUserAgent());
        }
        if (event.getTargetResource() != null) {
            historicalSummary.append(", Resource: ").append(event.getTargetResource());
        }
        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            historicalSummary.append(", Metadata: ").append(event.getMetadata().toString());
        }

        context.setHistoricalBehaviorSummary(historicalSummary.toString());

        return context;
    }

    /**
     * BehavioralAnalysisRequest 생성
     */
    private BehavioralAnalysisRequest createRequest(BehavioralAnalysisContext context, SecurityEvent event) {
        // BehavioralAnalysisRequest의 팩토리 메서드 사용
        String operation = String.format("analyze_%s", event.getEventType().toString().toLowerCase());
        BehavioralAnalysisRequest request = BehavioralAnalysisRequest.create(context, operation, event.getSessionId());

        return request;
    }

    /**
     * 비동기 행동 분석 실행
     */
    private CompletableFuture<BehavioralAnalysisResponse> executeBehavioralAnalysis(BehavioralAnalysisRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // processAsync를 사용하여 비동기 처리
                Mono<BehavioralAnalysisResponse> mono = behavioralAnalysisLab.processAsync(request);
                return mono.block();
            } catch (Exception e) {
                log.error("[BehavioralConnector] 랩 실행 오류", e);
                throw new RuntimeException("행동 분석 랩 실행 실패", e);
            }
        });
    }

    /**
     * BehavioralAnalysisResponse를 ThreatAssessment로 변환
     */
    private ThreatAssessment convertToThreatAssessment(
            BehavioralAnalysisResponse response, SecurityEvent event, String assessmentId) {

        // 위험 점수 계산
        double riskScore = calculateRiskScore(response);

        // 신뢰도 계산
        double confidence = calculateConfidence(response);

        // 위협 레벨 결정
        ThreatAssessment.ThreatLevel threatLevel = determineThreatLevel(riskScore);

        // 추천 액션 추출
        List<String> recommendedActions = extractRecommendedActions(response, riskScore);

        // 상세 정보 구성
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
            .threatLevel(threatLevel)
            .riskScore(riskScore)
            .confidence(confidence)
            .recommendedActions(recommendedActions)
            .metadata(details)
            .build();
    }

    /**
     * 위험 점수 계산
     */
    private double calculateRiskScore(BehavioralAnalysisResponse response) {
        double baseScore = 0.0;

        // Behavioral Risk Score 사용 (0-100을 0-1로 정규화)
        baseScore = response.getBehavioralRiskScore() / 100.0;

        // Risk Level로 추가 조정
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

        // Anomalies 수로 추가 조정
        if (response.getAnomalies() != null && !response.getAnomalies().isEmpty()) {
            double anomalyBonus = Math.min(response.getAnomalies().size() * 0.1, 0.3);
            baseScore += anomalyBonus;
        }

        return Math.min(baseScore, 1.0);
    }

    /**
     * 신뢰도 계산
     */
    private double calculateConfidence(BehavioralAnalysisResponse response) {
        double confidence = 0.7; // 기본값

        // 분석 데이터 품질에 따른 조정
        if (response.getAnomalies() != null && response.getAnomalies().size() > 0) {
            confidence += 0.1; // 이상 징후가 발견되면 신뢰도 증가
        }

        if (response.getRecommendations() != null && response.getRecommendations().size() > 0) {
            confidence += 0.1; // 추천 사항이 있으면 신뢰도 증가
        }

        if (response.getSummary() != null && !response.getSummary().trim().isEmpty()) {
            confidence += 0.1; // 분석 요약이 있으면 신뢰도 증가
        }

        // 최소 신뢰도 보장
        if (confidence < minConfidenceThreshold) {
            confidence = minConfidenceThreshold;
        }

        return Math.min(confidence, 1.0);
    }

    /**
     * 위협 레벨 결정
     */
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.9) {
            return ThreatAssessment.ThreatLevel.CRITICAL;
        } else if (riskScore >= 0.7) {
            return ThreatAssessment.ThreatLevel.HIGH;
        } else if (riskScore >= 0.5) {
            return ThreatAssessment.ThreatLevel.MEDIUM;
        } else if (riskScore >= 0.3) {
            return ThreatAssessment.ThreatLevel.LOW;
        } else {
            return ThreatAssessment.ThreatLevel.INFO;
        }
    }

    /**
     * 추천 액션 추출
     */
    private List<String> extractRecommendedActions(BehavioralAnalysisResponse response, double riskScore) {
        List<String> actions = new ArrayList<>();

        // 응답에서 추천 액션 추출 (action 필드만 추출)
        if (response.getRecommendations() != null) {
            response.getRecommendations().forEach(rec -> {
                if (rec.getAction() != null) {
                    actions.add(rec.getAction());
                }
            });
        }

        // 위험 점수 기반 추가 액션
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

    /**
     * 벡터 분석으로 평가 강화
     *
     * Vector Store에서 유사 행동 패턴을 검색하여 ThreatAssessment를 강화합니다.
     * 과거 행동 패턴과의 유사도를 기반으로 이상 점수를 계산하고 추가 컨텍스트를 제공합니다.
     */
    private void enrichWithVectorAnalysis(ThreatAssessment assessment, SecurityEvent event) {
        try {
            String userId = event.getUserId();
            String activity = event.getEventType().getDisplayName();

            // 1. Vector Store에서 유사 행동 패턴 검색 (상위 10개)
            List<org.springframework.ai.document.Document> similarBehaviors =
                behaviorVectorService.findSimilarBehaviors(userId, activity, 10);

            // 2. 유사 패턴 분석
            Map<String, Object> vectorAnalysis = analyzeSimilarBehaviors(similarBehaviors, event);

            // 3. 평가 메타데이터에 벡터 분석 결과 추가
            Map<String, Object> metadata = assessment.getMetadata();
            if (metadata == null) {
                metadata = new HashMap<>();
                assessment.setMetadata(metadata);
            }

            metadata.put("vectorAnalysisEnabled", true);
            metadata.put("vectorAnalysisResults", vectorAnalysis);
            metadata.put("similarPatternCount", similarBehaviors.size());

            // 4. 이상 점수 조정 (유사 패턴이 없으면 이상 점수 증가)
            if (vectorAnalysis.containsKey("anomalyScoreAdjustment")) {
                double adjustment = (Double) vectorAnalysis.get("anomalyScoreAdjustment");
                double currentRiskScore = assessment.getRiskScore();
                double adjustedRiskScore = Math.min(Math.max(currentRiskScore + adjustment, 0.0), 1.0);

                assessment.setRiskScore(adjustedRiskScore);
                metadata.put("riskScoreAdjusted", true);
                metadata.put("riskScoreAdjustment", adjustment);

                log.debug("[BehavioralConnector] 벡터 분석 기반 위험 점수 조정: {} → {}",
                    currentRiskScore, adjustedRiskScore);
            }

            // 5. 추천 액션 강화
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

            // 오류 발생 시에도 기본 메타데이터는 추가
            Map<String, Object> metadata = assessment.getMetadata();
            if (metadata == null) {
                metadata = new HashMap<>();
                assessment.setMetadata(metadata);
            }
            metadata.put("vectorAnalysisEnabled", false);
            metadata.put("vectorAnalysisError", e.getMessage());
        }
    }

    /**
     * 유사 행동 패턴 분석
     *
     * @param similarBehaviors 유사 행동 패턴 문서 목록
     * @param event 현재 보안 이벤트
     * @return 분석 결과 맵
     */
    private Map<String, Object> analyzeSimilarBehaviors(
            List<org.springframework.ai.document.Document> similarBehaviors, SecurityEvent event) {

        Map<String, Object> analysis = new HashMap<>();

        if (similarBehaviors.isEmpty()) {
            // 유사 패턴이 없음 = 매우 이상한 행동
            analysis.put("anomalyScoreAdjustment", 0.3); // 이상 점수 30% 증가
            analysis.put("pattern", "NO_SIMILAR_PATTERN");
            analysis.put("additionalActions", List.of("detailed_investigation", "behavior_baseline_update"));
            return analysis;
        }

        // 1. 평균 유사도 계산
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

        // 2. 과거 행동 패턴 요약
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

        // 3. 위험 행동 비율 계산
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

        // 4. 이상 점수 조정 계산
        if (avgSimilarity < vectorSimilarityThreshold) {
            // 유사도가 임계값보다 낮으면 이상 점수 증가
            double adjustment = (vectorSimilarityThreshold - avgSimilarity) * 0.3;
            analysis.put("anomalyScoreAdjustment", adjustment);
        } else if (riskBehaviorRatio > 0.5) {
            // 과거에 위험 행동이 50% 이상이면 이상 점수 증가
            analysis.put("anomalyScoreAdjustment", riskBehaviorRatio * 0.2);
        }

        // 5. 추천 액션 생성
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

        // 6. 패턴 분류
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

    /**
     * 비활성화 상태 평가
     */
    private ThreatAssessment createDisabledAssessment(SecurityEvent event) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator("BehavioralAnalysisLab-Disabled")
            .threatLevel(ThreatAssessment.ThreatLevel.INFO)
            .riskScore(0.5)
            .confidence(0.0)
            .recommendedActions(List.of("enable_behavioral_analysis"))
            .metadata(Map.of("status", "disabled"))
            .build();
    }

    /**
     * 오류 발생 시 평가
     */
    private ThreatAssessment createErrorAssessment(SecurityEvent event, String assessmentId, String error) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(assessmentId)
            .assessedAt(LocalDateTime.now())
            .evaluator("BehavioralAnalysisLab-Error")
            .threatLevel(ThreatAssessment.ThreatLevel.MEDIUM)
            .riskScore(0.5)
            .confidence(0.3)
            .recommendedActions(List.of("manual_review", "fallback_analysis"))
            .metadata(Map.of("error", error))
            .build();
    }
}