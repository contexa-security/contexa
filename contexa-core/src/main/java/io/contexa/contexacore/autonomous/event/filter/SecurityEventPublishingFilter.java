package io.contexa.contexacore.autonomous.event.filter;

import io.contexa.contexacore.autonomous.event.decision.UnifiedEventPublishingDecisionEngine;
import io.contexa.contexacore.autonomous.event.domain.HttpRequestEvent;
import io.contexa.contexacore.autonomous.utils.UserIdentificationStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
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
@RequiredArgsConstructor
public class SecurityEventPublishingFilter extends OncePerRequestFilter {

    private final ApplicationEventPublisher applicationEventPublisher;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final UnifiedEventPublishingDecisionEngine unifiedDecisionEngine;
    // Enterprise metrics - optional
    // private Object metricsCollector;

    @Value("${security.event.publishing.enabled:true}")
    private boolean eventPublishingEnabled;

    @Value("${security.event.publishing.anonymous.enabled:true}")
    private boolean anonymousEventPublishingEnabled;

    @Value("${security.event.publishing.exclude-uris:/actuator,/health,/metrics}")
    private String[] excludeUris;

    // Enterprise metrics setter - optional
    // public void setMetricsCollector(Object metricsCollector) {
    //     this.metricsCollector = metricsCollector;
    // }

    /**
     * HCADFilter가 설정한 request attribute 키 (v3.0 - AI Native)
     *
     * AI Native 아키텍처:
     * - LLM이 action, isAnomaly, riskScore를 직접 결정
     * - 규칙 기반 threshold 없음 (LLM이 모든 판단 수행)
     * - action이 핵심 판단 기준 (ALLOW/BLOCK/ESCALATE/MONITOR/INVESTIGATE)
     */
    private static final String HCAD_IS_ANOMALY = "hcad.is_anomaly";
    private static final String HCAD_RISK_SCORE = "hcad.risk_score";
    private static final String HCAD_ACTION = "hcad.action";

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

            Boolean hcadAuthCheck = (Boolean) request.getAttribute("hcad.is_authenticated");
            boolean isAuthenticated;
            Authentication auth = null;
            if (hcadAuthCheck != null) {
                isAuthenticated = hcadAuthCheck;
                log.trace("[SecurityEventPublishingFilter] Reusing auth check from HCADFilter: isAuthenticated={}", isAuthenticated);
            } else {
                auth = SecurityContextHolder.getContext().getAuthentication();
                isAuthenticated = auth != null && trustResolver.isAuthenticated(auth);
                log.trace("[SecurityEventPublishingFilter] Direct auth check (HCADFilter bypassed): isAuthenticated={}", isAuthenticated);
            }

            if (eventPublishingEnabled || isAuthenticated) {
                publishEventIfNeeded(request, response, auth);;
            }

        }
    }

    /**
     * HttpRequestEvent 발행
     *
     * Phase 4: Zero Trust 핵심 원칙 적용
     *
     * "인증자에 한해서는 무조건 이벤트를 발행해야 한다. 언제 공격자가 공격할지 아무도 모른다."
     *
     * 인증된 사용자:
     * - 캐싱 여부와 무관하게 **무조건 이벤트 발행**
     * - 공격자가 언제 어떤 행동을 하든 LLM 분석 수행
     *
     * 캐시와 이벤트 발행의 분리:
     * - 캐시 (HCADFilter): HCAD 분석 중복 방지 (성능 최적화)
     * - 이벤트 발행 (여기): Cold Path LLM 분석 트리거 (보안)
     */
    private void publishEventIfNeeded(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
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

            // 3. 인증 상태 확인
            boolean isAuthenticated = auth != null && trustResolver.isAuthenticated(auth);

            // Phase 4: Zero Trust 핵심 - 인증된 사용자는 캐시 히트와 무관하게 무조건 이벤트 발행
            // CRITICAL: 캐시 히트 체크를 인증된 사용자에게 적용하지 않음
            // 기존 설계 결함: 캐시 히트 시 인증 사용자도 이벤트 중단 → 공격 탐지 불가
            Boolean fromCache = (Boolean) request.getAttribute("hcad.from_cache");
            if (Boolean.TRUE.equals(fromCache) && !isAuthenticated) {
                // 익명 사용자만 캐시 히트 시 이벤트 스킵 (성능 최적화)
                log.debug("[SecurityEventPublishingFilter] Anonymous event skipped (cache hit): uri={}",
                         request.getRequestURI());
                return;
            }

            if (Boolean.TRUE.equals(fromCache) && isAuthenticated) {
                // 인증된 사용자: 캐시 히트여도 무조건 이벤트 발행 (Zero Trust)
                log.debug("[SecurityEventPublishingFilter][ZeroTrust] Authenticated user - publishing event despite cache hit: uri={}",
                         request.getRequestURI());
            }

            // AI Native: LLM이 action, isAnomaly, riskScore를 직접 결정
            Boolean hcadIsAnomaly = (Boolean) request.getAttribute(HCAD_IS_ANOMALY);
            Double hcadRiskScore = (Double) request.getAttribute(HCAD_RISK_SCORE);
            String hcadAction = (String) request.getAttribute(HCAD_ACTION);

            // 인증 사용자 이벤트 발행 결정
            String userId = "";
            UnifiedEventPublishingDecisionEngine.PublishingDecision decision = null;
            userId = UserIdentificationStrategy.getUserId(auth);
            // AI Native: action 기반 발행 결정 (LLM이 action 직접 결정)
            decision = unifiedDecisionEngine.decideAuthenticated(request, auth, userId,
                                                                  hcadAction, hcadIsAnomaly, hcadRiskScore);
            if (!decision.isShouldPublish()) {
                log.debug("[SecurityEventPublishingFilter] Authenticated event skipped by AI: userId={}, {}",
                         userId, decision);
                return;
            }

            log.debug("[SecurityEventPublishingFilter] Authenticated event approved by AI: userId={}, {}",
                     userId, decision);

            // Phase 9: 세션/사용자 컨텍스트 정보 조회 (HCADFilter에서 설정)
            Boolean isNewSession = (Boolean) request.getAttribute("hcad.is_new_session");
            Boolean isNewUser = (Boolean) request.getAttribute("hcad.is_new_user");
            Boolean isNewDevice = (Boolean) request.getAttribute("hcad.is_new_device");
            Integer recentRequestCount = (Integer) request.getAttribute("hcad.recent_request_count");

            HttpRequestEvent.HttpRequestEventBuilder eventBuilder = HttpRequestEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventTimestamp(LocalDateTime.now())
                .userId(userId)
                .sourceIp(extractClientIp(request))
                .userAgent(extractUserAgent(request))      // User-Agent 추출 (봇/정상 사용자 구별용)
                .requestUri(request.getRequestURI())
                .httpMethod(request.getMethod())
                .statusCode(response.getStatus())
                .hcadIsAnomaly(hcadIsAnomaly)              // AI Native: LLM이 직접 결정
                .hcadAnomalyScore(hcadRiskScore)           // AI Native: LLM이 결정한 위험도 점수
                .hcadAction(hcadAction)                    // AI Native: LLM이 결정한 action
                .authentication(auth)
                .isAnonymous(false)
                .eventTier(decision.getTier())
                .riskScore(decision.getRiskScore())
                .trustScore(decision.getTrustScore())
                // Phase 9: 세션/사용자 컨텍스트 정보 추가
                .isNewSession(isNewSession)
                .isNewUser(isNewUser)
                .isNewDevice(isNewDevice)
                .recentRequestCount(recentRequestCount);

            HttpRequestEvent event = eventBuilder.build();

            // ===== 메트릭 수집 =====
            long startTime = System.nanoTime();

            applicationEventPublisher.publishEvent(event);

            long duration = System.nanoTime() - startTime;

            // Enterprise metrics - optional
            // if (metricsCollector != null) {
            //     metricsCollector.recordHttpFilter(duration);
            //     metricsCollector.recordHttpRequest();
            //
            //     // EventRecorder 인터페이스를 통한 이벤트 기록
            //     Map<String, Object> metadata = new HashMap<>();
            //     metadata.put("uri", request.getRequestURI());
            //     metadata.put("method", request.getMethod());
            //     metadata.put("status", response.getStatus());
            //     metadata.put("duration", duration);
            //     metadata.put("user_id", userId);
            //     metadata.put("is_authenticated", isAuthenticated);
            //     metadata.put("tier", decision.getTier());
            //     metadata.put("risk_score", decision.getRiskScore());
            //
            //     metricsCollector.recordEvent("http_filter", metadata);
            // }

        log.debug("[SecurityEventPublishingFilter] Published HttpRequestEvent (AI Native): userId={}, uri={}, action={}, isAnomaly={}, Risk={:.3f}, Tier={}",
                 userId, request.getRequestURI(),
                 hcadAction, hcadIsAnomaly,
                 decision.getRiskScore(), decision.getTier());

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

    /**
     * User-Agent 추출 (테스트용 X-Simulated-User-Agent 헤더 우선)
     *
     * 브라우저 보안 정책으로 User-Agent 헤더를 직접 수정할 수 없어서
     * 테스트 환경에서는 X-Simulated-User-Agent 커스텀 헤더를 사용합니다.
     *
     * @param request HTTP 요청
     * @return User-Agent 문자열 (curl, python-requests 등 봇 구별에 사용)
     */
    private String extractUserAgent(HttpServletRequest request) {
        // 테스트용 X-Simulated-User-Agent 헤더 우선 읽기
        String userAgent = request.getHeader("X-Simulated-User-Agent");
        if (userAgent != null && !userAgent.isEmpty()) {
            return userAgent;
        }

        // 실제 User-Agent 헤더 읽기
        userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }
}
