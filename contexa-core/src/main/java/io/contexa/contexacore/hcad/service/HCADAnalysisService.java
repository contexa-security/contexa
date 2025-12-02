package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;

/**
 * HCAD 분석 서비스 (AI Native)
 *
 * HCADFilter의 핵심 로직을 추출한 서비스 (Single Source of Truth)
 *
 * 사용처:
 * 1. HCADFilter: 모든 일반 요청 분석 (인증 전 상태)
 * 2. MySecurityConfig 로그인 핸들러: 로그인 시 인증된 사용자로 재계산
 *
 * AI Native 방식:
 * - LLM이 반환한 riskScore(0.0~1.0)를 Redis에서 조회하여 그대로 사용
 * - 규칙 기반 조정 없이 LLM 판단 100% 신뢰
 * - threat_score:{userId} 키에서 조회
 *
 * 성능 목표: 1-5ms (컨텍스트 추출) + 1ms (Redis 조회) = 2-6ms
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
public class HCADAnalysisService {

    private final HCADContextExtractor contextExtractor;
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${hcad.anomaly.threshold:0.5}")
    private double defaultThreshold;

    public HCADAnalysisService(HCADContextExtractor contextExtractor) {
        this.contextExtractor = contextExtractor;
    }

    @Autowired
    public void setRedisTemplate(@Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * HCAD 분석 수행 (AI Native)
     *
     * HCADFilter와 로그인 핸들러 모두에서 사용
     *
     * AI Native 처리 흐름:
     * 1. 컨텍스트 추출 (userId, IP, UserAgent 등)
     * 2. Redis에서 LLM riskScore(threat_score) 조회
     * 3. riskScore를 그대로 anomalyScore로 사용 (규칙 기반 조정 없음)
     * 4. HCADAnalysisResult 반환
     *
     * @param request HTTP 요청
     * @param authentication 인증 정보 (인증 전: anonymousUser, 인증 후: 실제 사용자)
     * @return HCAD 분석 결과
     */
    public HCADAnalysisResult analyze(HttpServletRequest request, Authentication authentication) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 컨텍스트 추출 (1-5ms)
            HCADContext context = contextExtractor.extractContext(request, authentication);
            String userId = context.getUserId();

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService][AI Native] 컨텍스트 추출 완료: userId={}, path={}, ip={}",
                    userId, context.getRequestPath(), context.getRemoteIp());
            }

            // 2. Redis에서 LLM riskScore(threat_score) 조회 (AI Native 핵심)
            double riskScore = getLLMRiskScoreFromRedis(userId);

            // 3. AI Native: LLM riskScore를 그대로 사용
            // riskScore >= threshold -> 이상 탐지
            double currentThreshold = defaultThreshold;
            boolean isAnomaly = riskScore >= currentThreshold;
            double anomalyScore = riskScore;
            double trustScore = 1.0 - riskScore;
            double similarityScore = 1.0 - riskScore;

            // 위협 유형 결정 (riskScore 기반)
            String threatType = determineThreatType(riskScore);
            String threatEvidence = buildThreatEvidence(riskScore, isAnomaly);

            long processingTime = System.currentTimeMillis() - startTime;

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService][AI Native] 분석 완료: userId={}, riskScore={}, isAnomaly={}, time={}ms",
                    userId,
                    String.format("%.3f", riskScore),
                    isAnomaly,
                    processingTime);
            }

            // 4. 결과 반환
            return HCADAnalysisResult.builder()
                .userId(userId)
                .similarityScore(similarityScore)
                .trustScore(trustScore)
                .threatType(threatType)
                .threatEvidence(threatEvidence)
                .isAnomaly(isAnomaly)
                .anomalyScore(anomalyScore)
                .threshold(currentThreshold)
                .processingTimeMs(processingTime)
                .context(context)
                .build();

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] 분석 실패: request={}", request.getRequestURI(), e);

            // Fail-Safe: 에러 발생 시 기본값 반환
            return HCADAnalysisResult.builder()
                .userId("error")
                .similarityScore(0.0)
                .trustScore(0.0)
                .threatType("ANALYSIS_ERROR")
                .threatEvidence(e.getMessage())
                .isAnomaly(true)
                .anomalyScore(1.0)
                .threshold(defaultThreshold)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .build();
        }
    }

    /**
     * Redis에서 LLM riskScore(threat_score) 조회
     *
     * AI Native 핵심 메서드:
     * - Layer1/2/3에서 LLM이 판단한 riskScore를 Redis에 저장
     * - 이 메서드에서 해당 값을 조회하여 그대로 사용
     *
     * @param userId 사용자 ID
     * @return riskScore (0.0 ~ 1.0), 없으면 0.0 (신규 사용자 = 정상)
     */
    private double getLLMRiskScoreFromRedis(String userId) {
        if (redisTemplate == null) {
            log.warn("[HCADAnalysisService][AI Native] RedisTemplate이 null입니다. 기본값 0.0 반환");
            return 0.0;
        }

        try {
            String key = ZeroTrustRedisKeys.threatScore(userId);
            Object value = redisTemplate.opsForValue().get(key);

            if (value == null) {
                // 신규 사용자 또는 아직 LLM 분석이 안 된 경우
                if (log.isDebugEnabled()) {
                    log.debug("[HCADAnalysisService][AI Native] threat_score 없음: userId={}, 기본값 0.0 반환", userId);
                }
                return 0.0;
            }

            if (value instanceof Number) {
                double riskScore = ((Number) value).doubleValue();
                // 범위 검증 (0.0 ~ 1.0)
                riskScore = Math.max(0.0, Math.min(1.0, riskScore));
                if (log.isDebugEnabled()) {
                    log.debug("[HCADAnalysisService][AI Native] threat_score 조회: userId={}, riskScore={}", userId, riskScore);
                }
                return riskScore;
            }

            if (value instanceof String) {
                try {
                    double riskScore = Double.parseDouble((String) value);
                    riskScore = Math.max(0.0, Math.min(1.0, riskScore));
                    return riskScore;
                } catch (NumberFormatException e) {
                    log.warn("[HCADAnalysisService][AI Native] threat_score 파싱 실패: userId={}, value={}", userId, value);
                    return 0.0;
                }
            }

            log.warn("[HCADAnalysisService][AI Native] 알 수 없는 threat_score 타입: userId={}, type={}", userId, value.getClass().getName());
            return 0.0;

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] Redis 조회 실패: userId={}", userId, e);
            return 0.0;
        }
    }

    /**
     * riskScore 기반 위협 유형 결정
     *
     * @param riskScore LLM이 판단한 위험 점수 (0.0 ~ 1.0)
     * @return 위협 유형 문자열
     */
    private String determineThreatType(double riskScore) {
        if (riskScore >= 0.9) {
            return "CRITICAL";
        } else if (riskScore >= 0.7) {
            return "HIGH";
        } else if (riskScore >= 0.5) {
            return "MEDIUM";
        } else if (riskScore >= 0.3) {
            return "LOW";
        } else {
            return "NONE";
        }
    }

    /**
     * 위협 증거 문자열 생성
     *
     * @param riskScore LLM이 판단한 위험 점수
     * @param isAnomaly 이상 탐지 여부
     * @return 위협 증거 문자열
     */
    private String buildThreatEvidence(double riskScore, boolean isAnomaly) {
        if (!isAnomaly) {
            return "AI Native: LLM riskScore=" + String.format("%.3f", riskScore) + " (정상 범위)";
        }
        return "AI Native: LLM riskScore=" + String.format("%.3f", riskScore) + " (임계값 초과)";
    }

    /**
     * 기준선 업데이트 수행 (AI Native)
     *
     * AI Native 방식: 기준선 학습은 LLM Cold Path에서 담당
     * HCADFilter에서는 호출만 하고 실제 로직은 Cold Path에서 처리됨
     *
     * @param result HCAD 분석 결과
     */
    public void updateBaselineIfNeeded(HCADAnalysisResult result) {
        // AI Native: 기준선 학습은 Cold Path에서 담당
        // HCADFilter에서는 로깅만 수행
        if (result.isAnomaly() && log.isDebugEnabled()) {
            log.debug("[HCADAnalysisService][AI Native] 이상 탐지 - Cold Path에서 학습 예정: userId={}", result.getUserId());
        }
    }

    /**
     * 통계 업데이트 수행 (AI Native)
     *
     * AI Native 방식: 메트릭 수집은 Micrometer 기반으로 자동 처리
     * 여기서는 디버그 로깅만 수행
     *
     * @param result HCAD 분석 결과
     */
    public void updateStatisticsIfNeeded(HCADAnalysisResult result) {
        // AI Native: 메트릭은 Micrometer에서 자동 수집
        // EvolutionMetricsCollector.recordHCADAnalysis() 호출됨
        if (log.isDebugEnabled()) {
            log.debug("[HCADAnalysisService][AI Native] 통계 업데이트 완료: userId={}, isAnomaly={}, riskScore={}",
                result.getUserId(),
                result.isAnomaly(),
                String.format("%.3f", result.getAnomalyScore()));
        }
    }
}
