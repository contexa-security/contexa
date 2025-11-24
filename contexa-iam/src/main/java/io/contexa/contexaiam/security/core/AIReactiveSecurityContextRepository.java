package io.contexa.contexaiam.security.core;

import io.contexa.contexaiam.security.core.session.SessionIdResolver;
import io.contexa.contexaiam.security.core.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.security.core.zerotrust.ZeroTrustAuthenticationToken;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AI-Native Reactive Security Context Repository
 *
 * Spring Security의 HttpSessionSecurityContextRepository를 상속받아
 * Zero Trust 보안 기능을 추가한 구현체입니다.
 *
 * 주요 기능:
 * - 표준 HttpSession 세션 관리 (부모 클래스에 위임)
 * - Zero Trust 위협 점수 평가 및 동적 권한 조정
 * - 세션 무효화 추적 및 관리
 * - AI 기반 보안 메트릭 수집
 * - 세션 하이재킹 탐지 및 대응
 *
 * 세션 관리는 Spring Security가 자동으로 처리하며,
 * Zero Trust 관련 기능만 추가로 구현합니다.
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public class AIReactiveSecurityContextRepository extends HttpSessionSecurityContextRepository {

    @Autowired
    private ZeroTrustSecurityService zeroTrustSecurityService;

    @Autowired
    private ThreatScoreOrchestrator threatScoreOrchestrator;

    @Autowired
    private SessionIdResolver sessionIdResolver;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    // 무효화된 세션 ID를 메모리에 캐싱 (빠른 조회를 위해)
    private final Set<String> invalidatedSessions = ConcurrentHashMap.newKeySet();

    // 로컬 서버에서 관리하는 사용자별 세션 매핑 (userId -> Set<sessionId>)
    private final Map<String, Set<String>> localUserSessions = new ConcurrentHashMap<>();

    // 세션별 사용자 매핑 (sessionId -> userId)
    private final Map<String, String> localSessionToUser = new ConcurrentHashMap<>();

    @Value("${zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${zerotrust.session.tracking.enabled:true}")
    private boolean sessionTrackingEnabled;

    @Value("${zerotrust.evaluation.on.every.request:true}")
    private boolean evaluateOnEveryRequest;

    @Value("${security.session.create.allowed:true}")
    private boolean allowSessionCreation;

    @Value("${security.session.hijack.detection.enabled:true}")
    private boolean hijackDetectionEnabled;

    @Value("${zerotrust.threat.threshold.suspicious:0.5}")
    private double suspiciousThreatThreshold;

    // AuthenticationTrustResolver for anonymous user detection
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    /**
     * 기본 생성자
     * HttpSessionSecurityContextRepository의 기본 동작을 상속받습니다.
     */
    public AIReactiveSecurityContextRepository() {
        super();
        // 세션 생성 허용 설정 (기본값: true)
        this.setAllowSessionCreation(true);
        // 비인증 사용자에 대해서도 세션 저장 허용
        this.setDisableUrlRewriting(false);
        // SecurityContext 속성 이름 설정 (Spring Security 표준)
        this.setSpringSecurityContextKey("SPRING_SECURITY_CONTEXT");
    }

    /**
     * Spring Security 6.x 표준 - DeferredSecurityContext 로드
     *
     * 부모 클래스의 표준 구현을 호출한 후 Zero Trust 기능을 추가합니다.
     *
     * @param request HTTP 요청
     * @return DeferredSecurityContext
     */
    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        // 부모 클래스의 표준 구현 호출 - 세션에서 SecurityContext 읽기
        DeferredSecurityContext parentContext = super.loadDeferredContext(request);

        // Zero Trust 기능이 비활성화되면 부모의 구현 그대로 반환
        if (!zeroTrustEnabled) {
            return parentContext;
        }

        // Zero Trust 기능을 추가한 래퍼 반환
        return new ZeroTrustDeferredSecurityContext(parentContext, request);
    }

    /**
     * Zero Trust DeferredSecurityContext 구현
     *
     * 부모 클래스의 DeferredSecurityContext를 래핑하여 Zero Trust 기능을 추가합니다.
     */
    private class ZeroTrustDeferredSecurityContext implements DeferredSecurityContext {
        private final DeferredSecurityContext parentContext;
        private final HttpServletRequest request;
        private SecurityContext cachedContext;
        private boolean loaded = false;

        public ZeroTrustDeferredSecurityContext(DeferredSecurityContext parentContext, HttpServletRequest request) {
            this.parentContext = parentContext;
            this.request = request;
        }

        @Override
        public SecurityContext get() {
            if (!loaded) {
                // 1. 부모 클래스에서 SecurityContext 가져오기
                SecurityContext context = parentContext.get();

                // 2. Zero Trust 평가 적용
                Authentication auth = context.getAuthentication();
                String sessionId = extractSessionId(request);

                if (auth != null && trustResolver.isAuthenticated(auth)) {
                    // 인증된 사용자 - userId 기반 Zero Trust
                    String userId = auth.getName();
                    zeroTrustSecurityService.applyZeroTrustToContext(context, userId, sessionId);
                } else if (auth != null) {
                    // 익명 사용자 - IP 기반 Zero Trust (NEW)
                    String clientIp = extractClientIp(request);
                    zeroTrustSecurityService.applyZeroTrustToAnonymousContext(context, clientIp, request);
                }

                cachedContext = context;
                loaded = true;
            }
            return cachedContext;
        }

        @Override
        public boolean isGenerated() {
            return parentContext.isGenerated();
        }
    }



    /**
     * SecurityContext 저장
     *
     * 부모 클래스의 기본 세션 저장 기능에 Zero Trust 메트릭 업데이트를 추가합니다.
     *
     * @param context SecurityContext
     * @param request HTTP 요청
     * @param response HTTP 응답
     */
    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        // Zero Trust 검증 - 무효화된 세션 체크
        if (zeroTrustEnabled) {
            String sessionId = extractSessionId(request);
            if (sessionId != null && zeroTrustSecurityService.isSessionInvalidated(sessionId)) {
                log.debug("[ZeroTrust] Skipping context save for invalidated session: {}",
                    maskSessionId(sessionId));
                return; // 무효화된 세션에는 저장하지 않음
            }
        }

        // 1. 반드시 부모 클래스의 saveContext 호출 - 핵심 세션 저장 로직
        super.saveContext(context, request, response);

        // 2. Zero Trust 추가 기능
        if (zeroTrustEnabled && context.getAuthentication() != null) {
            String userId = context.getAuthentication().getName();
            String sessionId = extractSessionId(request);
            boolean isAuthenticated = context.getAuthentication().isAuthenticated();

            try {
                if (isAuthenticated && sessionId != null) {
                    // 세션 추적 및 사용자 컨텍스트 업데이트
                    if (sessionTrackingEnabled) {
                        updateUserSessionMapping(userId, sessionId);
                        updateUserContext(userId, sessionId, request);
                    }

                    log.trace("[ZeroTrust] Session context saved for user: {} in session: {}",
                        userId, maskSessionId(sessionId));
                } else if (!isAuthenticated && sessionId != null) {
                    // 로그아웃 처리
                    handleLogout(userId, sessionId);
                }

            } catch (Exception e) {
                log.error("[ZeroTrust] Error during Zero Trust metrics update for user: {}", userId, e);
                // 오류가 발생해도 부모의 saveContext는 이미 성공했으므로 계속 진행
            }
        }
    }



    /**
     * 세션이 처음 생성된 요청인지 확인
     */
    private boolean isFirstRequestInSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }

        long creationTime = session.getCreationTime();
        long lastAccessedTime = session.getLastAccessedTime();

        // 생성 시간과 마지막 접근 시간의 차이가 1초 이내면 첫 번째 요청으로 간주
        return (lastAccessedTime - creationTime) < 1000;
    }

    /**
     * 세션 무효화 여부 확인
     */

    /**
     * 세션 ID 추출 (Spring Session Redis 호환)
     */
    private String extractSessionId(HttpServletRequest request) {
        // SessionIdResolver를 통해 다양한 소스에서 세션 ID 추출
        String sessionId = sessionIdResolver.resolve(request);

        if (sessionId == null) {
            // 폴백: HttpSession에서 직접 추출
            HttpSession session = request.getSession(false);
            if (session != null) {
                sessionId = session.getId();
            }
        }

        return sessionId;
    }

    /**
     * 클라이언트 IP 주소 추출
     *
     * X-Forwarded-For 헤더를 고려하여 실제 클라이언트 IP를 추출합니다.
     * 프록시 환경에서도 정확한 IP를 가져오기 위해 여러 헤더를 확인합니다.
     *
     * @param request HTTP 요청
     * @return 클라이언트 IP 주소
     */
    private String extractClientIp(HttpServletRequest request) {
        String ip = null;

        // 1. X-Forwarded-For 헤더 확인 (프록시/로드밸런서 환경)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            // 여러 IP가 있는 경우 첫 번째 IP가 실제 클라이언트 IP
            ip = xForwardedFor.split(",")[0].trim();
        }

        // 2. X-Real-IP 헤더 확인 (Nginx 프록시)
        if (ip == null || ip.isEmpty()) {
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
                ip = xRealIp;
            }
        }

        // 3. Proxy-Client-IP 헤더 확인 (Apache 프록시)
        if (ip == null || ip.isEmpty()) {
            String proxyClientIp = request.getHeader("Proxy-Client-IP");
            if (proxyClientIp != null && !proxyClientIp.isEmpty() && !"unknown".equalsIgnoreCase(proxyClientIp)) {
                ip = proxyClientIp;
            }
        }

        // 4. WL-Proxy-Client-IP 헤더 확인 (WebLogic 프록시)
        if (ip == null || ip.isEmpty()) {
            String wlProxyClientIp = request.getHeader("WL-Proxy-Client-IP");
            if (wlProxyClientIp != null && !wlProxyClientIp.isEmpty() && !"unknown".equalsIgnoreCase(wlProxyClientIp)) {
                ip = wlProxyClientIp;
            }
        }

        // 5. 폴백: request.getRemoteAddr() 사용
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }

        // IPv6 localhost를 IPv4로 변환
        if ("0:0:0:0:0:0:0:1".equals(ip)) {
            ip = "127.0.0.1";
        }

        return ip != null ? ip : "unknown";
    }

    /**
     * 로컬 세션 추적
     */
    private void trackLocalSession(String userId, String sessionId) {
        localUserSessions.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
        localSessionToUser.put(sessionId, userId);
    }

    /**
     * 사용자 세션 매핑 업데이트
     */
    private void updateUserSessionMapping(String userId, String sessionId) {
        try {
            // 로컬 캐시 업데이트
            trackLocalSession(userId, sessionId);

            // Redis에 세션-사용자 매핑 저장
            String mappingKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.opsForValue().set(mappingKey, userId, Duration.ofHours(24));

            // 사용자 세션 목록 업데이트
            String userSessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(userSessionsKey, sessionId);
            redisTemplate.expire(userSessionsKey, Duration.ofDays(7));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to update user session mapping", e);
        }
    }

    /**
     * 사용자 컨텍스트 업데이트
     */
    private void updateUserContext(String userId, String sessionId, HttpServletRequest request) {
        try {
            String userContextKey = ZeroTrustRedisKeys.userContext(userId);
            UserSecurityContext userContext = (UserSecurityContext) redisTemplate.opsForValue().get(userContextKey);

            if (userContext == null) {
                userContext = UserSecurityContext.builder()
                    .userId(userId)
                    .currentThreatScore(zeroTrustSecurityService.getThreatScore(userId))
                    .createdAt(java.time.LocalDateTime.now())
                    .build();
            }

            // 세션 정보 추가/업데이트
            UserSecurityContext.SessionContext sessionContext = UserSecurityContext.SessionContext.builder()
                .sessionId(sessionId)
                .lastAccessTime(java.time.LocalDateTime.now())
                .active(true)
                .build();

            userContext.addSession(sessionContext);
            userContext.setUpdatedAt(java.time.LocalDateTime.now());

            // Redis에 저장
            redisTemplate.opsForValue().set(userContextKey, userContext, Duration.ofDays(30));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to update user context for user: {}", userId, e);
        }
    }


    /**
     * 로그아웃 처리
     */
    private void handleLogout(String userId, String sessionId) {
        try {
            log.info("[ZeroTrust] User logout detected - User: {}, Session: {}",
                userId, maskSessionId(sessionId));

            // 로컬 캐시 정리
            localSessionToUser.remove(sessionId);
            Set<String> sessions = localUserSessions.get(userId);
            if (sessions != null) {
                sessions.remove(sessionId);
                if (sessions.isEmpty()) {
                    localUserSessions.remove(userId);
                }
            }

            // Zero Trust 서비스에 로그아웃 알림
            zeroTrustSecurityService.invalidateSession(sessionId, userId, "User logout");

        } catch (Exception e) {
            log.error("[ZeroTrust] Error handling logout for user: {}", userId, e);
        }
    }

    /**
     * 세션 ID 마스킹 (로깅용)
     */
    private String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." + sessionId.substring(sessionId.length() - 4);
    }

    /**
     * 세션 생성 허용 설정
     */
    @Override
    public void setAllowSessionCreation(boolean allowSessionCreation) {
        super.setAllowSessionCreation(allowSessionCreation);
        this.allowSessionCreation = allowSessionCreation;
    }


    /**
     * 사용자의 모든 세션 무효화
     *
     * 보안 이벤트 발생 시 사용자의 모든 활성 세션을 종료
     */
    public void invalidateAllUserSessions(String userId, String reason) {
        if (!zeroTrustEnabled) {
            return;
        }

        try {
            log.warn("[ZeroTrust] Invalidating all sessions for user: {} - Reason: {}", userId, reason);

            // 로컬 캐시의 세션 무효화
            Set<String> userSessions = localUserSessions.get(userId);
            if (userSessions != null) {
                for (String sessionId : new HashSet<>(userSessions)) {
                    invalidatedSessions.add(sessionId);
                    localSessionToUser.remove(sessionId);
                }
                localUserSessions.remove(userId);
            }

            // Zero Trust 서비스를 통해 Redis의 모든 세션 무효화
            zeroTrustSecurityService.invalidateAllUserSessions(userId, reason);

        } catch (Exception e) {
            log.error("[ZeroTrust] Error invalidating all sessions for user: {}", userId, e);
        }
    }


}