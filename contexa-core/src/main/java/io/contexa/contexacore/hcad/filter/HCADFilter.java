package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacore.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.hcad.service.*;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * HCAD (Hyper-lightweight Context Anomaly Detector) 필터 (v3.0)
 *
 * Spring Security 필터 체인에 통합되어 모든 요청을 실시간으로 검사
 * - 초경량 AI 모델을 사용하여 5-30ms 내에 이상 탐지 및 차단 결정
 * - HCADAnalysisService를 사용하여 유사도 계산 (Single Source of Truth)
 * - 로그인 요청도 포함하여 모든 요청 분석 (로그인 핸들러에서 재계산)
 *
 * 위치: SecurityContextHolderFilter 직후, UsernamePasswordAuthenticationFilter 이전
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
//@Component
public class HCADFilter extends OncePerRequestFilter {

    private final HCADAnalysisService hcadAnalysisService;
    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final HCADAuthenticationService authenticationService;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Value("${hcad.enabled:true}")
    private boolean enabled;

    @Value("${hcad.threshold.warn:0.7}")
    private double warnThreshold;

    @Value("${hcad.cache.clear-on-startup:false}")
    private boolean clearCacheOnStartup;



    @PostConstruct
    public void init() {
        if (clearCacheOnStartup) {
            clearBaselineCache();
        }
        log.info("[HCAD] Filter initialized - enabled: {}, warnThreshold: {}, clearCacheOnStartup: {}",
            enabled, warnThreshold, clearCacheOnStartup);
    }

    private void clearBaselineCache() {
        try {
            String pattern = HCADRedisKeys.userHcadPattern("*");
            Set<String> keys = redisTemplate.keys(pattern);
            if (keys != null && !keys.isEmpty()) {
                Long deletedCount = redisTemplate.delete(keys);
                log.warn("[HCAD] Cleared {} baseline cache entries from Redis (package migration)", deletedCount);
            } else {
                log.info("[HCAD] No baseline cache entries found to clear");
            }
        } catch (Exception e) {
            log.error("[HCAD] Failed to clear baseline cache", e);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // HCAD 가 비활성화되어 있으면 통과
        if (!enabled) {
            filterChain.doFilter(request, response);
            return;
        }

        // 인증 여부 확인 (인증/익명 사용자 모두 처리)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        // PERFORMANCE FIX: 인증 여부를 request attribute로 저장하여
        // SecurityEventPublishingFilter 에서 재사용 (중복 체크 방지)
        request.setAttribute("hcad.is_authenticated", isAuthenticated);

        try {
            // 1. HCAD 분석 수행
            HCADAnalysisResult result = hcadAnalysisService.analyze(request, authentication);

            // 2. request attribute에 저장 (SecurityEventPublishingFilter 에서 재사용)
            request.setAttribute("hcad.similarity_score", result.getSimilarityScore());
            request.setAttribute("hcad.trust_score", result.getTrustScore());
            request.setAttribute("hcad.threat_type", result.getThreatType());
            request.setAttribute("hcad.threat_evidence", result.getThreatEvidence());
            request.setAttribute("hcad.is_anomaly", result.isAnomaly());
            request.setAttribute("hcad.anomaly_score", result.getAnomalyScore());
            request.setAttribute("hcad.threshold", result.getThreshold());

            if (log.isDebugEnabled()) {
                log.debug("[HCADFilter] 분석 완료: {}", result);
            }

            // 3. 기준선 업데이트
            hcadAnalysisService.updateBaselineIfNeeded(result);

            // 4. 이상탐지 시 Authentication.details에 저장
            if (result.isAnomaly()) {
                authenticationService.setAnomalyInfoInAuthentication(
                    authentication,
                    result.getContext(),
                    result.getSimilarityScore(),
                    result.getAnomalyScore(),
                    result.getThreshold()
                );
                log.warn("[HCADFilter] Anomaly detected - userId: {}, similarity: {}, threshold: {}",
                    result.getUserId(), String.format("%.3f", result.getSimilarityScore()), result.getThreshold());
            }

            // 5. 통계 업데이트
            hcadAnalysisService.updateStatisticsIfNeeded(result);

            // 6. 메트릭은 HCADAnalysisService에서 자동으로 수집됨 (Micrometer 기반)
            // EvolutionMetricsCollector.recordHCADAnalysis() 호출됨

            // 요청 통과
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("[HCAD] 처리 중 오류 발생", e);
            // 오류 발생 시 안전하게 통과 (fail-open)
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 정적 리소스, 헬스체크, 메트릭 수집 경로는 필터링하지 않음
        String path = request.getRequestURI();
        return path.startsWith("/static/") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/health") ||
               path.startsWith("/actuator/") ||  // 모든 Actuator 엔드포인트 제외 (메트릭 포함)
               path.startsWith("/api/admin/test/vectorstore");  // VectorStore 테스트 컨트롤러 제외
    }


}