package io.contexa.contexacore.autonomous.event.filter;

import io.contexa.contexacore.autonomous.event.decision.UnifiedEventPublishingDecisionEngine;
import io.contexa.contexacore.autonomous.event.domain.HttpRequestEvent;
import io.contexa.contexacore.dashboard.metrics.zerotrust.EventPublishingMetrics;
import io.contexa.contexacore.autonomous.utils.UserIdentificationStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Security Event Publishing Filter (Spring Event Pattern)
 *
 * 일반 HTTP 요청 완료 후 HttpRequestEvent를 발행하여
 * ZeroTrustEventListener가 처리하도록 합니다.
 *
 * 핵심 원칙:
 * 1. HCADFilter는 유사도 계산만 수행 (책임 분리)
 * 2. 이 필터는 일반 요청에 대한 HttpRequestEvent 발행만 (Spring Event Pattern)
 * 3. 특수 이벤트(로그인, @Protectable, 인가실패)는 각 핸들러에서 별도 발행 후 플래그 설정
 * 4. 플래그 기반 중복 방지: "security.event.published" 플래그 체크
 * 5. ZeroTrustEventListener가 SecurityEvent로 변환 후 발행
 * 6. AI 기반 통합 샘플링:
 *    - 익명: (1.0 - HCAD) * 0.7 + ipThreat * 0.3
 *    - 인증: (1.0 - HCAD) * 0.5 + (1.0 - trustScore) * 0.5
 * 7. Hot Path(BENIGN)도 10% 샘플링 → 피드백 루프 연결
 * 8. Event Storm 방지: 인증 사용자도 샘플링 (71% 부하 감소)
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityEventPublishingFilter extends OncePerRequestFilter {

    private final ApplicationEventPublisher applicationEventPublisher;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final UnifiedEventPublishingDecisionEngine unifiedDecisionEngine;
    private EventPublishingMetrics metricsCollector;

    @Value("${security.event.publishing.enabled:true}")
    private boolean eventPublishingEnabled;

    @Value("${security.event.publishing.anonymous.enabled:true}")
    private boolean anonymousEventPublishingEnabled;

    @Value("${security.event.publishing.exclude-uris:/actuator,/health,/metrics}")
    private String[] excludeUris;

    public void setMetricsCollector(EventPublishingMetrics metricsCollector) {
        this.metricsCollector = metricsCollector;
    }

    /**
     * HCADFilter가 설정한 request attribute 키 (v2.0 - 피드백 루프 완전 통합)
     */
    private static final String HCAD_SIMILARITY_SCORE = "hcad.similarity_score";
    private static final String HCAD_IS_ANOMALY = "hcad.is_anomaly";
    private static final String HCAD_ANOMALY_SCORE = "hcad.anomaly_score";
    private static final String HCAD_THRESHOLD = "hcad.threshold";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 메트릭 수집 경로와 VectorStore 테스트 경로 제외
        String path = request.getRequestURI();
        return path.startsWith("/actuator/") ||
               path.startsWith("/api/admin/test/vectorstore");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } finally {
            // 요청 완료 후 이벤트 발행 (응답에 영향 없음)
            if (eventPublishingEnabled) {
                publishEventIfNeeded(request, response);
            }
        }
    }

    /**
     * HttpRequestEvent 발행
     */
    private void publishEventIfNeeded(HttpServletRequest request,
                                      HttpServletResponse response) {
        try {
            // 1. URI 제외 목록 체크
            if (shouldExcludeUri(request.getRequestURI())) {
                log.trace("[SecurityEventPublishingFilter] URI excluded from event publishing: {}", request.getRequestURI());
                return;
            }

            // 2. 이벤트 발행 플래그 체크 (중복 이벤트 방지)
            Boolean eventPublished = (Boolean) request.getAttribute("security.event.published");
            if (Boolean.TRUE.equals(eventPublished)) {
                log.debug("[SecurityEventPublishingFilter] Event already published by specific handler, skipping general event: uri={}",
                         request.getRequestURI());
                return;
            }

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            // HCAD 피드백 루프 완전 통합 (v2.0) - 모든 HCAD 결과 읽기
            Double hcadSimilarity = (Double) request.getAttribute(HCAD_SIMILARITY_SCORE);
            Boolean hcadIsAnomaly = (Boolean) request.getAttribute(HCAD_IS_ANOMALY);
            Double hcadAnomalyScore = (Double) request.getAttribute(HCAD_ANOMALY_SCORE);
            Double hcadThreshold = (Double) request.getAttribute(HCAD_THRESHOLD);

            // HCADFilter가 실행되지 않은 경우(비인증 요청)에는 직접 체크
            Boolean hcadAuthCheck = (Boolean) request.getAttribute("hcad.is_authenticated");
            boolean isAuthenticated;

            if (hcadAuthCheck != null) {
                // HCADFilter가 이미 인증 체크함 → 재사용 (성능 최적화)
                isAuthenticated = hcadAuthCheck;
                log.trace("[SecurityEventPublishingFilter] Reusing auth check from HCADFilter: isAuthenticated={}", isAuthenticated);
            } else {
                // HCADFilter 미실행 (비인증 요청) → 직접 체크
                isAuthenticated = auth != null && trustResolver.isAuthenticated(auth);
                log.trace("[SecurityEventPublishingFilter] Direct auth check (HCADFilter bypassed): isAuthenticated={}", isAuthenticated);
            }

            // 2. 인증 사용자 vs 익명 사용자 구분
            String userId;
            UnifiedEventPublishingDecisionEngine.PublishingDecision decision;

            if (isAuthenticated) {
                // 인증된 사용자 - Trust Score 기반 AI 샘플링 (v2.0 - 피드백 루프 완전 통합)
                userId = UserIdentificationStrategy.getUserId(auth);

                // AI 기반 발행 결정 (HCAD + Trust Score + 피드백 학습 결과)
                decision = unifiedDecisionEngine.decideAuthenticated(request, auth, userId, hcadSimilarity,
                                                                      hcadIsAnomaly, hcadAnomalyScore);

                if (!decision.isShouldPublish()) {
                    log.debug("[SecurityEventPublishingFilter] Authenticated event skipped by AI: userId={}, {}",
                             userId, decision);
                    return;
                }

                log.debug("[SecurityEventPublishingFilter] Authenticated event approved by AI: userId={}, {}",
                         userId, decision);
            } else {
                // 익명 사용자 - IP 위협 기반 AI 샘플링 (v2.0 - 피드백 루프 완전 통합)
                userId = "anonymous:" + extractClientIp(request);

                if (!anonymousEventPublishingEnabled) {
                    log.trace("[SecurityEventPublishingFilter] Anonymous event publishing disabled");
                    return;
                }

                // AI 기반 발행 결정 (HCAD + IP 위협 + 시스템 상태 + 피드백 학습 결과)
                decision = unifiedDecisionEngine.decideAnonymous(request, hcadSimilarity,
                                                                 hcadIsAnomaly, hcadAnomalyScore);

                if (!decision.isShouldPublish()) {
                    log.debug("[SecurityEventPublishingFilter] Anonymous event skipped by AI: {}",
                             decision);
                    return;
                }

                log.debug("[SecurityEventPublishingFilter] Anonymous event approved by AI: {}", decision);
            }

            // 3. HttpRequestEvent 발행 (Spring Event Pattern) - v2.0 피드백 루프 완전 통합
            HttpRequestEvent.HttpRequestEventBuilder eventBuilder = HttpRequestEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventTimestamp(LocalDateTime.now())
                .userId(userId)
                .sourceIp(extractClientIp(request))
                .requestUri(request.getRequestURI())
                .httpMethod(request.getMethod())
                .statusCode(response.getStatus())
                .hcadSimilarityScore(hcadSimilarity)
                .hcadIsAnomaly(hcadIsAnomaly)              // 학습된 임계값 기반 이상 탐지 판정
                .hcadAnomalyScore(hcadAnomalyScore)        // 이상 점수
                .hcadThreshold(hcadThreshold)              // 사용된 학습 임계값
                .authentication(auth)
                .isAnonymous(!isAuthenticated)
                .eventTier(decision.getTier())
                .riskScore(decision.getRiskScore());

            // 인증 사용자면 Trust Score 추가
            if (isAuthenticated) {
                eventBuilder.trustScore(decision.getTrustScore());
            } else {
                // 익명 사용자면 IP 위협 점수 추가
                eventBuilder.ipThreatScore(decision.getIpThreatScore());
            }

            HttpRequestEvent event = eventBuilder.build();

            // ===== 메트릭 수집 =====
            long startTime = System.nanoTime();

            applicationEventPublisher.publishEvent(event);

            long duration = System.nanoTime() - startTime;

            if (metricsCollector != null) {
                metricsCollector.recordHttpFilter(duration);
                metricsCollector.recordHttpRequest();

                // EventRecorder 인터페이스를 통한 이벤트 기록
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("uri", request.getRequestURI());
                metadata.put("method", request.getMethod());
                metadata.put("status", response.getStatus());
                metadata.put("duration", duration);
                metadata.put("user_id", userId);
                metadata.put("is_authenticated", isAuthenticated);
                metadata.put("tier", decision.getTier());
                metadata.put("risk_score", decision.getRiskScore());

                metricsCollector.recordEvent("http_filter", metadata);
            }

            if (isAuthenticated) {
                log.debug("[SecurityEventPublishingFilter] Published HttpRequestEvent (Authenticated): userId={}, uri={}, HCAD={:.3f}, Trust={:.3f}, Risk={:.3f}, Tier={}",
                         userId, request.getRequestURI(),
                         hcadSimilarity != null ? hcadSimilarity : 0.0,
                         decision.getTrustScore(), decision.getRiskScore(), decision.getTier());
            } else {
                log.debug("[SecurityEventPublishingFilter] Published HttpRequestEvent (Anonymous): userId={}, uri={}, HCAD={:.3f}, IP Threat={:.3f}, Risk={:.3f}, Tier={}",
                         userId, request.getRequestURI(),
                         hcadSimilarity != null ? hcadSimilarity : 0.0,
                         decision.getIpThreatScore(), decision.getRiskScore(), decision.getTier());
            }

        } catch (Exception e) {
            // 이벤트 발행 실패가 요청 처리를 중단시키지 않도록
            log.error("[SecurityEventPublishingFilter] Failed to publish HttpRequestEvent", e);
        }
    }

    /**
     * URI가 제외 목록에 포함되는지 확인
     *
     * @param uri 요청 URI
     * @return true면 이벤트 발행 제외
     */
    private boolean shouldExcludeUri(String uri) {
        if (uri == null || excludeUris == null) {
            return false;
        }

        for (String excludePattern : excludeUris) {
            if (uri.startsWith(excludePattern.trim())) {
                return true;
            }
        }

        return false;
    }

    /**
     * 클라이언트 IP 추출 (프록시 고려)
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
