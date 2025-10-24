package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 벡터 유사도 기반 평가 핸들러
 *
 * HCADFilter 에서 계산된 벡터 유사도 점수를 가져와서
 * SecurityEventContext에 저장하고 라우팅 결정을 위한 준비를 합니다.
 *
 * 역할:
 * - Request attribute에서 유사도 점수 추출 (HCADFilter가 계산한 값)
 * - SecurityEvent metadata에서 유사도 점수 추출 (인증 이벤트의 경우)
 * - 유사도 점수를 컨텍스트에 저장
 * - 신뢰도와 위험도 계산
 * - HOT/COLD Path 라우팅 권장사항 생성 (Layer 1/2/3)
 *
 * 라우팅 정책 (2025-01 최적화):
 * - HOT Path (similarity > 0.70): HCAD 벡터 분석만으로 충분 (90% 요청)
 * - Layer 1 (0.55 < similarity ≤ 0.70): TinyLlama 빠른 분석 (6% 요청)
 * - Layer 2 (0.40 < similarity ≤ 0.55): Llama3.1 상세 분석 (3% 요청)
 * - Layer 3 (similarity ≤ 0.40): Claude 전문가 분석 (1% 요청)
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
public class VectorSimilarityHandler implements SecurityEventHandler {

    @Value("${security.plane.agent.similarity-threshold:0.70}")
    private double highSimilarityThreshold;

    @Value("${security.plane.agent.layer1-threshold:0.55}")
    private double layer1Threshold;

    @Value("${security.plane.agent.layer2-threshold:0.40}")
    private double layer2Threshold;

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.debug("[VectorSimilarityHandler] Processing event: {}", event.getEventId());

        try {
            // ===== Priority 1: SecurityEvent 필드에서 직접 가져오기 (최우선) =====
            Double similarityScore = event.getHcadSimilarityScore();
            if (similarityScore != null) {
                log.info("[VectorSimilarityHandler] Using HCAD from SecurityEvent field: eventId={}, score={}",
                         event.getEventId(), String.format("%.3f", similarityScore));
            }

            // ===== Priority 2: Request attribute 에서 가져오기 (HTTP 요청) =====
            if (similarityScore == null) {
                similarityScore = extractSimilarityFromRequest();
                if (similarityScore != null) {
                    log.info("[VectorSimilarityHandler] Using HCAD from request attribute: eventId={}, score={}",
                             event.getEventId(), String.format("%.3f", similarityScore));
                }
            }

            // ===== Priority 3: SecurityEvent metadata 에서 가져오기 (하위 호환성) =====
            if (similarityScore == null) {
                similarityScore = extractSimilarityFromEvent(event);
                if (similarityScore != null) {
                    log.info("[VectorSimilarityHandler] Using HCAD from metadata (legacy): eventId={}, score={}",
                             event.getEventId(), String.format("%.3f", similarityScore));
                }
            }

            // ===== Priority 4: HCAD 데이터 없음 - 기본값으로 처리 =====
            if (similarityScore == null) {
                log.warn("[VectorSimilarityHandler] HCAD similarity not found for event: {}", event.getEventId());
                setDefaultValues(context);
                return true;
            }

            // 2. 유사도 점수를 컨텍스트에 저장
            context.addMetadata("similarityScore", similarityScore);

            // 3. 위험 점수 계산 (유사도의 역)
            double riskScore = 1.0 - similarityScore;
            context.addMetadata("vectorRiskScore", riskScore);

            // 4. 신뢰도 계산
            double confidence = calculateConfidence(similarityScore);
            context.addMetadata("vectorConfidence", confidence);

            // 5. 유사도 레벨 분류
            String similarityLevel = categorizeSimilarity(similarityScore);
            context.addMetadata("similarityLevel", similarityLevel);

            // 6. 처리 권장사항 설정
            setRecommendations(context, similarityScore, riskScore);

            log.info("[VectorSimilarityHandler] Event {} - similarity: {}, risk: {}, confidence: {}, level: {}",
                event.getEventId(),
                String.format("%.3f", similarityScore),
                String.format("%.3f", riskScore),
                String.format("%.3f", confidence),
                similarityLevel);

            // 7. AI 분석 결과 생성 (RoutingDecisionHandler와 호환성 유지)
            SecurityEventContext.AIAnalysisResult aiResult = SecurityEventContext.AIAnalysisResult.builder()
                .threatLevel(riskScore)
                .confidenceScore(confidence)
                .summary(String.format("Vector similarity: %.3f, Risk: %.3f", similarityScore, riskScore))
                .aiModel("VectorSimilarity")
                .analysisTimeMs(System.currentTimeMillis() - context.getCreatedAt().toInstant(java.time.ZoneOffset.UTC).toEpochMilli())
                .build();

            context.setAiAnalysisResult(aiResult);

            return true; // 다음 핸들러로 진행

        } catch (Exception e) {
            log.error("[VectorSimilarityHandler] Error processing event: {}", event.getEventId(), e);
            // 오류 발생 시 기본값 설정
            setDefaultValues(context);
            return true; // 오류에도 불구하고 계속 진행
        }
    }

    /**
     * SecurityEvent metadata에서 HCAD 유사도 추출 (인증 이벤트용)
     *
     * 인증 성공 이벤트는 HCADFilter를 거치지 않으므로 (인증 전이라 통과),
     * AuthenticationSuccessHandler에서 계산한 HCAD 유사도를 SecurityEvent metadata에서 가져옵니다.
     *
     * @param event SecurityEvent
     * @return HCAD 유사도 (0.0 ~ 1.0) 또는 null
     */
    private Double extractSimilarityFromEvent(SecurityEvent event) {
        try {
            if (event.getMetadata() != null) {
                Object hcadScore = event.getMetadata().get("hcadSimilarityScore");
                if (hcadScore instanceof Double) {
                    return (Double) hcadScore;
                } else if (hcadScore instanceof Number) {
                    return ((Number) hcadScore).doubleValue();
                }
            }
        } catch (Exception e) {
            log.debug("[VectorSimilarityHandler] Failed to extract HCAD from event metadata", e);
        }
        return null;
    }

    /**
     * Request attribute 에서 유사도 점수 추출 (HTTP 요청용)
     */
    private Double extractSimilarityFromRequest() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                Object similarityObj = request.getAttribute("hcad.similarity_score");
                if (similarityObj instanceof Double) {
                    return (Double) similarityObj;
                }
            }
        } catch (Exception e) {
            log.debug("[VectorSimilarityHandler] Unable to extract similarity from request", e);
        }
        return null;
    }


    /**
     * 신뢰도 계산 (유사도 점수 기반)
     * 신뢰도 = 사용자를 얼마나 신뢰할 수 있는가 (유사도가 높을수록 신뢰)
     */
    private double calculateConfidence(double similarityScore) {
        // 높은 유사도 = 높은 신뢰도 (정상 행동 패턴)
        // 낮은 유사도 = 낮은 신뢰도 (의심스러운 행동)
        if (similarityScore > 0.9) {
            return 0.95;  // 매우 신뢰
        } else if (similarityScore > 0.8) {
            return 0.85;  // 신뢰
        } else if (similarityScore > 0.7) {
            return 0.75;  // 보통
        } else if (similarityScore > 0.5) {
            return 0.5;   // 의심
        } else if (similarityScore > 0.3) {
            return 0.3;   // 매우 의심
        } else {
            return 0.1;   // 거의 신뢰 불가 (명백한 이상 행동)
        }
    }

    /**
     * 유사도 레벨 분류 (설정 가능한 임계값 사용)
     */
    private String categorizeSimilarity(double similarityScore) {
        if (similarityScore > highSimilarityThreshold) {
            return "HIGH_SIMILARITY"; // 정상 패턴과 매우 유사
        } else if (similarityScore > layer1Threshold) {
            return "MODERATE_SIMILARITY"; // 중간 유사도
        } else if (similarityScore > layer2Threshold) {
            return "LOW_SIMILARITY"; // 낮은 유사도
        } else {
            return "ANOMALY"; // 이상 징후
        }
    }

    /**
     * 처리 권장사항 설정
     */
    private void setRecommendations(SecurityEventContext context, double similarityScore, double riskScore) {
        if (similarityScore > highSimilarityThreshold) {
            // 높은 유사도 (>0.70): HOT Path - HCAD 분석으로 충분
            context.addMetadata("recommendedPath", "HOT_PATH");
            context.addMetadata("recommendedAction", "PASS_THROUGH");
            context.addResponseAction("ALLOW", "High similarity (>0.70) - HCAD analysis sufficient");
        } else if (similarityScore > layer1Threshold) {
            // 중간 유사도 (0.55~0.70): COLD Path Layer 1 - TinyLlama 분석
            context.addMetadata("recommendedPath", "COLD_PATH_L1");
            context.addMetadata("recommendedAction", "LAYER1_ANALYSIS");
            context.addResponseAction("MONITOR", "Moderate similarity - Layer 1 TinyLlama analysis required");
        } else if (similarityScore > layer2Threshold) {
            // 낮은 유사도 (0.40~0.55): COLD Path Layer 2 - Llama3.1 분석
            context.addMetadata("recommendedPath", "COLD_PATH_L2");
            context.addMetadata("recommendedAction", "LAYER2_ANALYSIS");
            context.addResponseAction("INVESTIGATE", "Low similarity - Layer 2 Llama3.1 analysis required");
        } else {
            // 매우 낮은 유사도 (≤0.40): COLD Path Layer 3 - Claude 전문가 분석
            context.addMetadata("recommendedPath", "COLD_PATH_L3");
            context.addMetadata("recommendedAction", "LAYER3_ANALYSIS");
            context.addResponseAction("BLOCK", "Very low similarity (≤0.40) - Layer 3 expert analysis required");
        }

        // Zero Trust 원칙: HOT Path 외 모든 경우 AI 분석 필요
        if (similarityScore <= highSimilarityThreshold) {
            context.addMetadata("requiresAIAnalysis", true);
        }
    }

    /**
     * 오류 시 기본값 설정
     */
    private void setDefaultValues(SecurityEventContext context) {
        // Zero Trust 원칙: 오류 시 보수적 접근
        context.addMetadata("similarityScore", 0.5);
        context.addMetadata("vectorRiskScore", 0.5);
        context.addMetadata("vectorConfidence", 0.5);
        context.addMetadata("similarityLevel", "UNKNOWN");
        context.addMetadata("recommendedPath", "COLD_PATH");
        context.addMetadata("recommendedAction", "INVESTIGATE");
        context.addMetadata("requiresAIAnalysis", true);

        // 호환성을 위한 AI 결과
        SecurityEventContext.AIAnalysisResult aiResult = SecurityEventContext.AIAnalysisResult.builder()
            .threatLevel(0.5)
            .confidenceScore(0.5)
            .summary("Vector similarity calculation failed - using default values")
            .aiModel("VectorSimilarity")
            .analysisTimeMs(0L)
            .build();

        context.setAiAnalysisResult(aiResult);
    }

    @Override
    public String getName() {
        return "VectorSimilarityHandler";
    }

    @Override
    public int getOrder() {
        return 15; // ValidationHandler(10) 다음, RoutingDecisionHandler(40) 이전
    }
}