package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;
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

    // D3: LLM 분석 결과 최대 유효 시간 (기본: 1시간)
    @Value("${hcad.analysis.max-age-ms:3600000}")
    private long analysisMaxAgeMs;

    // AI Native 전환: defaultThreshold 제거
    // - LLM이 isAnomaly를 직접 판단하여 Redis에 저장
    // - 임계값 기반 판단 로직 제거

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

            // 2. Redis에서 LLM 분석 결과 조회 (AI Native 핵심)
            // LLM이 판단한 모든 값을 그대로 조회 - 규칙 기반 계산 제거
            Map<String, Object> llmAnalysis = getLLMAnalysisFromRedis(userId);

            // 3. AI Native: LLM 분석 결과를 그대로 사용 (규칙 기반 판단 제거)
            double riskScore = (double) llmAnalysis.getOrDefault("riskScore", 0.0);
            boolean isAnomaly = (boolean) llmAnalysis.getOrDefault("isAnomaly", false);
            double anomalyScore = riskScore;
            // AI Native: trustScore도 LLM이 직접 반환 (자동 계산 제거)
            double trustScore = (double) llmAnalysis.getOrDefault("trustScore", 1.0);

            // AI Native: 위협 유형도 LLM이 직접 반환 (규칙 기반 분류 제거)
            String threatType = (String) llmAnalysis.getOrDefault("threatType", "NONE");
            String threatEvidence = (String) llmAnalysis.getOrDefault("threatEvidence", "");

            // AI Native: action과 confidence (핵심 필드) - LLM이 직접 반환
            // Phase 17: LLM 미분석 시 action=null 반환 → EventTier.CRITICAL → 100% 발행
            String action = (String) llmAnalysis.get("action");  // null 허용 (캐시 미스 구분)
            double confidence = (double) llmAnalysis.getOrDefault("confidence", Double.NaN);

            long processingTime = System.currentTimeMillis() - startTime;

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService][AI Native] 분석 완료: userId={}, action={}, riskScore={}, isAnomaly={}, confidence={}, time={}ms",
                    userId,
                    action,
                    String.format("%.3f", riskScore),
                    isAnomaly,
                    String.format("%.3f", confidence),
                    processingTime);
            }

            // 4. 결과 반환 (AI Native: action 기반 판단 - LLM이 action 직접 결정)
            return HCADAnalysisResult.builder()
                .userId(userId)
                .trustScore(trustScore)
                .threatType(threatType)
                .threatEvidence(threatEvidence)
                .isAnomaly(isAnomaly)
                .anomalyScore(anomalyScore)
                .action(action)  // AI Native: LLM이 결정한 action
                .confidence(confidence)  // AI Native: LLM이 결정한 confidence
                // AI Native v4.2.0: .threshold() 삭제 - 필드 제거됨
                .processingTimeMs(processingTime)
                .context(context)
                .build();

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] 분석 실패: request={}", request.getRequestURI(), e);

            // Zero Trust v6.0: 예외 경로에서도 보수적인 context 설정
            // 이전 문제: context가 null → isNewSession, isNewDevice, recentRequestCount 미설정
            // 수정: 예외 시 보수적 기본값 (모두 신규/미확인 상태로 간주)
            HCADContext errorContext = new HCADContext();
            errorContext.setIsNewSession(true);      // 예외 시 신규 세션으로 간주 (보수적)
            errorContext.setIsNewDevice(true);       // 예외 시 신규 디바이스로 간주 (보수적)
            errorContext.setRecentRequestCount(0);   // 예외 시 요청 카운트 불명

            // AI Native: 에러 발생 시에도 규칙 기반 기본값 사용 안 함
            // 단순히 분석 실패 상태만 표시
            // Phase 17: 에러 시에도 action=null → EventTier.CRITICAL → 100% 발행
            return HCADAnalysisResult.builder()
                .userId("error")
                .trustScore(Double.NaN)
                .threatType("ANALYSIS_ERROR")
                .threatEvidence("LLM 분석 조회 실패: " + e.getMessage())
                .isAnomaly(false) // AI Native: 분석 실패 시 이상으로 간주하지 않음 (LLM이 판단해야 함)
                .anomalyScore(Double.NaN)
                .action(null)  // Phase 17: 분석 실패 시 null → CRITICAL → 100% 발행
                .confidence(Double.NaN)
                // AI Native v4.2.0: .threshold() 삭제 - 필드 제거됨
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .context(errorContext)  // Zero Trust v6.0: 예외 시에도 context 설정
                .build();
        }
    }

    /**
     * Redis에서 LLM 분석 결과 조회 (AI Native)
     *
     * AI Native 핵심 메서드:
     * - Layer1/2/3에서 LLM이 판단한 모든 결과를 Redis에 저장
     * - 이 메서드에서 해당 값들을 조회하여 그대로 반환 (가공 없음)
     *
     * LLM 저장 스키마:
     * - riskScore: 위험도 점수 (0.0 ~ 1.0)
     * - isAnomaly: 이상 여부 (true/false)
     * - trustScore: 신뢰도 점수 (0.0 ~ 1.0)
     * - threatType: 위협 유형 (CRITICAL/HIGH/MEDIUM/LOW/NONE)
     * - threatEvidence: 위협 증거 (자유 형식)
     *
     * @param userId 사용자 ID
     * @return LLM 분석 결과 Map (값이 없으면 기본값 포함)
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> getLLMAnalysisFromRedis(String userId) {
        Map<String, Object> result = new HashMap<>();

        // AI Native: 기본값은 "분석 미수행" 상태 (규칙 기반 기본값 제거)
        // LLM 분석 결과가 없는 신규 사용자는 NaN으로 명시
        result.put("riskScore", Double.NaN);
        result.put("isAnomaly", false);  // 분석 안됨 = 이상 아님 (차단하지 않음)
        result.put("trustScore", Double.NaN);  // AI Native: 신뢰도 미측정
        result.put("threatType", "NOT_ANALYZED");
        result.put("threatEvidence", "LLM analysis not yet performed for this user");
        // Phase 17: action 기본값 설정 안함 (null) → EventTier.CRITICAL → 100% 발행
        // result.put("action", null);  // 명시적으로 null 설정하지 않음 (HashMap.get()이 null 반환)
        result.put("confidence", Double.NaN);  // AI Native: 신뢰도 미측정

        if (redisTemplate == null) {
            log.warn("[HCADAnalysisService][AI Native] RedisTemplate이 null입니다. 기본값 반환");
            return result;
        }

        try {
            // LLM 분석 결과 조회 (Hash 구조)
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<Object, Object> analysis = redisTemplate.opsForHash().entries(analysisKey);

            if (analysis != null && !analysis.isEmpty()) {
                // D3: 분석 결과 신선도 검증
                boolean isStale = false;
                if (analysis.containsKey("analyzedAt")) {
                    long analyzedAt = parseLong(analysis.get("analyzedAt"));
                    long ageMs = System.currentTimeMillis() - analyzedAt;
                    if (ageMs > analysisMaxAgeMs) {
                        isStale = true;
                        log.warn("[HCADAnalysisService][D3] Stale LLM analysis detected: userId={}, age={}ms, maxAge={}ms",
                            userId, ageMs, analysisMaxAgeMs);
                    }
                } else {
                    // analyzedAt 필드 없음 - 레거시 데이터로 간주
                    log.debug("[HCADAnalysisService][D3] No analyzedAt field, treating as legacy data: userId={}", userId);
                }
                result.put("isStale", isStale);

                // AI Native: LLM이 저장한 값을 그대로 사용 (clamp 연산 제거)
                if (analysis.containsKey("riskScore")) {
                    result.put("riskScore", parseDouble(analysis.get("riskScore")));
                }
                if (analysis.containsKey("isAnomaly")) {
                    result.put("isAnomaly", parseBoolean(analysis.get("isAnomaly")));
                }
                if (analysis.containsKey("trustScore")) {
                    result.put("trustScore", parseDouble(analysis.get("trustScore")));
                }
                if (analysis.containsKey("threatType")) {
                    result.put("threatType", analysis.get("threatType").toString());
                }
                if (analysis.containsKey("threatEvidence")) {
                    result.put("threatEvidence", analysis.get("threatEvidence").toString());
                }
                // AI Native: action과 confidence 조회 (핵심 필드)
                if (analysis.containsKey("action")) {
                    result.put("action", analysis.get("action").toString());
                }
                if (analysis.containsKey("confidence")) {
                    result.put("confidence", parseDouble(analysis.get("confidence")));
                }

                if (log.isDebugEnabled()) {
                    log.debug("[HCADAnalysisService][AI Native] LLM 분석 결과 조회: userId={}, action={}, riskScore={}, isAnomaly={}, confidence={}, isStale={}",
                        userId, result.get("action"), result.get("riskScore"), result.get("isAnomaly"), result.get("confidence"), isStale);
                }
            }
            // Dead Code 제거 (AI Native v4.0): 레거시 threat_score 조회 fallback 삭제
            // - AI Native에서는 hcadAnalysis 키만 사용
            // - 레거시 키 호환성 유지 불필요 (LLM 분석 결과가 없으면 기본값 사용)

        } catch (Exception e) {
            log.error("[HCADAnalysisService][AI Native] Redis 조회 실패: userId={}", userId, e);
        }

        return result;
    }

    /**
     * Object를 double로 파싱 (AI Native: clamp 연산 제거)
     */
    private double parseDouble(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    /**
     * Object를 boolean으로 파싱
     */
    private boolean parseBoolean(Object value) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return false;
    }

    /**
     * D3: Object를 long으로 파싱 (analyzedAt 타임스탬프용)
     */
    private long parseLong(Object value) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    // AI Native 전환: determineThreatType(), buildThreatEvidence() 메서드 제거
    // - 위협 유형과 증거는 LLM이 직접 판단하여 Redis에 저장
    // - 규칙 기반 분류 로직 완전 제거

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

    // Dead Code 제거 (AI Native v4.0): updateStatisticsIfNeeded() 삭제
    // - 외부 호출처 없음
    // - 로깅만 수행, 실제 통계 업데이트 없음
    // - 메트릭 수집은 Micrometer EvolutionMetricsCollector에서 자동 처리
}
