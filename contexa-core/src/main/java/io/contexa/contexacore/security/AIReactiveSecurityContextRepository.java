package io.contexa.contexacore.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
    private SessionIdResolver sessionIdResolver;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    // 무효화된 세션 캐시 (TTL 기반 자동 만료로 메모리 누수 방지)
    private Cache<String, Boolean> invalidatedSessionsCache;

    // 사용자별 세션 매핑 캐시 (TTL 기반 자동 만료)
    private Cache<String, Set<String>> userSessionsCache;

    // 세션별 사용자 매핑 캐시 (TTL 기반 자동 만료)
    private Cache<String, String> sessionToUserCache;

    // 세션별 마지막 Redis 업데이트 시간 (중복 호출 방지)
    private Cache<String, Instant> lastRedisUpdateCache;

    // 로그아웃 판단을 위한 이전 인증 상태 캐시
    private Cache<String, String> previousAuthCache;

    // 캐시 정리용 스케줄러
    private ScheduledExecutorService cacheCleanupScheduler;

    @Value("${zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${zerotrust.session.tracking.enabled:true}")
    private boolean sessionTrackingEnabled;

    @Value("${zerotrust.cache.session.ttl-minutes:30}")
    private int sessionCacheTtlMinutes;

    @Value("${zerotrust.cache.invalidated.ttl-minutes:60}")
    private int invalidatedCacheTtlMinutes;

    @Value("${zerotrust.redis.update-interval-seconds:30}")
    private int redisUpdateIntervalSeconds;

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
     * 빈 초기화 - Caffeine 캐시 설정
     * TTL 기반 자동 만료로 메모리 누수 방지
     */
    @PostConstruct
    public void initCaches() {
        // 무효화된 세션 캐시 (1시간 TTL)
        invalidatedSessionsCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(invalidatedCacheTtlMinutes, TimeUnit.MINUTES)
            .build();

        // 사용자별 세션 매핑 캐시 (30분 TTL)
        userSessionsCache = Caffeine.newBuilder()
            .maximumSize(5000)
            .expireAfterAccess(sessionCacheTtlMinutes, TimeUnit.MINUTES)
            .build();

        // 세션별 사용자 매핑 캐시 (30분 TTL)
        sessionToUserCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterAccess(sessionCacheTtlMinutes, TimeUnit.MINUTES)
            .build();

        // 마지막 Redis 업데이트 시간 캐시 (5분 TTL)
        lastRedisUpdateCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();

        // 이전 인증 상태 캐시 (세션 TTL과 동일)
        previousAuthCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterAccess(sessionCacheTtlMinutes, TimeUnit.MINUTES)
            .build();

        // 주기적 캐시 통계 로깅 (선택적)
        cacheCleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ZeroTrust-Cache-Monitor");
            t.setDaemon(true);
            return t;
        });

        cacheCleanupScheduler.scheduleAtFixedRate(this::logCacheStats, 5, 5, TimeUnit.MINUTES);

        log.info("[ZeroTrust] Cache initialized - sessionTtl: {}min, invalidatedTtl: {}min, redisInterval: {}s",
            sessionCacheTtlMinutes, invalidatedCacheTtlMinutes, redisUpdateIntervalSeconds);
    }

    /**
     * 빈 소멸 - 스케줄러 정리
     */
    @PreDestroy
    public void destroyCaches() {
        if (cacheCleanupScheduler != null && !cacheCleanupScheduler.isShutdown()) {
            cacheCleanupScheduler.shutdown();
            try {
                if (!cacheCleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    cacheCleanupScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                cacheCleanupScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        log.info("[ZeroTrust] Cache cleanup completed");
    }

    /**
     * 캐시 통계 로깅
     */
    private void logCacheStats() {
        if (log.isDebugEnabled()) {
            log.debug("[ZeroTrust] Cache stats - invalidated: {}, userSessions: {}, sessionToUser: {}",
                invalidatedSessionsCache.estimatedSize(),
                userSessionsCache.estimatedSize(),
                sessionToUserCache.estimatedSize());
        }
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
                    zeroTrustSecurityService.applyZeroTrustToContext(context, userId, sessionId, request);
                }
                // AI Native: 익명 사용자 Zero Trust 제거 - 인증된 사용자만 처리

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
        String sessionId = extractSessionId(request);

        // Zero Trust 검증 - 무효화된 세션 체크 (Caffeine 캐시 사용)
        if (zeroTrustEnabled && sessionId != null) {
            Boolean isInvalidated = invalidatedSessionsCache.getIfPresent(sessionId);
            if (isInvalidated != null && isInvalidated) {
                log.debug("[ZeroTrust] Skipping context save for invalidated session: {}",
                    maskSessionId(sessionId));
                return;
            }
            // 캐시 미스 시 Redis 확인
            if (isInvalidated == null && zeroTrustSecurityService.isSessionInvalidated(sessionId)) {
                invalidatedSessionsCache.put(sessionId, true);
                log.debug("[ZeroTrust] Skipping context save for invalidated session: {}",
                    maskSessionId(sessionId));
                return;
            }
        }

        // 1. 반드시 부모 클래스의 saveContext 호출 - 핵심 세션 저장 로직
        super.saveContext(context, request, response);

        // 2. Zero Trust 추가 기능
        if (zeroTrustEnabled && sessionId != null) {
            Authentication auth = context.getAuthentication();

            try {
                if (auth != null && isActuallyAuthenticated(auth)) {
                    String userId = auth.getName();

                    // 이전 인증 상태 저장 (로그아웃 판단용)
                    previousAuthCache.put(sessionId, userId);

                    // 세션 추적 및 사용자 컨텍스트 업데이트 (중복 호출 방지)
                    if (sessionTrackingEnabled && shouldUpdateRedis(sessionId)) {
                        updateUserSessionMapping(userId, sessionId);
                        updateUserContext(userId, sessionId, request);
                        lastRedisUpdateCache.put(sessionId, Instant.now());
                    }

                    log.trace("[ZeroTrust] Session context saved for user: {} in session: {}",
                        userId, maskSessionId(sessionId));
                } else if (isLogoutDetected(auth, sessionId)) {
                    // 실제 로그아웃 감지: 이전에 인증된 사용자가 있었고, 현재 인증이 없거나 Anonymous인 경우
                    String previousUserId = previousAuthCache.getIfPresent(sessionId);
                    if (previousUserId != null) {
                        handleLogout(previousUserId, sessionId);
                        previousAuthCache.invalidate(sessionId);
                    }
                }

            } catch (Exception e) {
                String userId = auth != null ? auth.getName() : "unknown";
                log.error("[ZeroTrust] Error during Zero Trust metrics update for user: {}", userId, e);
                // 오류가 발생해도 부모의 saveContext는 이미 성공했으므로 계속 진행
            }
        }
    }

    /**
     * 실제 인증된 사용자인지 확인 (AnonymousAuthenticationToken 제외)
     */
    private boolean isActuallyAuthenticated(Authentication auth) {
        if (auth == null) {
            return false;
        }
        if (auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        return auth.isAuthenticated() && trustResolver.isAuthenticated(auth);
    }

    /**
     * 로그아웃 여부 감지
     * - 이전에 인증된 사용자가 있었고
     * - 현재 Authentication이 null이거나 Anonymous인 경우
     */
    private boolean isLogoutDetected(Authentication auth, String sessionId) {
        String previousUserId = previousAuthCache.getIfPresent(sessionId);
        if (previousUserId == null) {
            // 이전에 인증된 기록이 없으면 로그아웃이 아님
            return false;
        }
        // 현재 인증이 없거나 Anonymous이면 로그아웃
        return auth == null || auth instanceof AnonymousAuthenticationToken || !auth.isAuthenticated();
    }

    /**
     * Redis 업데이트가 필요한지 확인 (중복 호출 방지)
     */
    private boolean shouldUpdateRedis(String sessionId) {
        Instant lastUpdate = lastRedisUpdateCache.getIfPresent(sessionId);
        if (lastUpdate == null) {
            return true;
        }
        // 설정된 간격(기본 30초)이 지났으면 업데이트
        return Instant.now().isAfter(lastUpdate.plusSeconds(redisUpdateIntervalSeconds));
    }

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
     * 로컬 세션 추적 (Caffeine 캐시 사용)
     */
    private void trackLocalSession(String userId, String sessionId) {
        // 사용자별 세션 목록 캐시
        Set<String> sessions = userSessionsCache.get(userId, k -> ConcurrentHashMap.newKeySet());
        sessions.add(sessionId);

        // 세션별 사용자 매핑 캐시
        sessionToUserCache.put(sessionId, userId);
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
     * 로그아웃 처리 (Caffeine 캐시 사용)
     */
    private void handleLogout(String userId, String sessionId) {
        try {
            log.info("[ZeroTrust] User logout detected - User: {}, Session: {}",
                userId, maskSessionId(sessionId));

            // Caffeine 캐시 정리
            sessionToUserCache.invalidate(sessionId);
            Set<String> sessions = userSessionsCache.getIfPresent(userId);
            if (sessions != null) {
                sessions.remove(sessionId);
                if (sessions.isEmpty()) {
                    userSessionsCache.invalidate(userId);
                }
            }

            // 무효화된 세션으로 표시
            invalidatedSessionsCache.put(sessionId, true);

            // 마지막 업데이트 캐시 정리
            lastRedisUpdateCache.invalidate(sessionId);

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
    }


    /**
     * 사용자의 모든 세션 무효화 (Caffeine 캐시 사용)
     *
     * 보안 이벤트 발생 시 사용자의 모든 활성 세션을 종료
     */
    public void invalidateAllUserSessions(String userId, String reason) {
        if (!zeroTrustEnabled) {
            return;
        }

        try {
            log.warn("[ZeroTrust] Invalidating all sessions for user: {} - Reason: {}", userId, reason);

            // Caffeine 캐시의 세션 무효화
            Set<String> userSessions = userSessionsCache.getIfPresent(userId);
            if (userSessions != null) {
                for (String sessionId : new HashSet<>(userSessions)) {
                    invalidatedSessionsCache.put(sessionId, true);
                    sessionToUserCache.invalidate(sessionId);
                    lastRedisUpdateCache.invalidate(sessionId);
                    previousAuthCache.invalidate(sessionId);
                }
                userSessionsCache.invalidate(userId);
            }

            // Zero Trust 서비스를 통해 Redis의 모든 세션 무효화
            zeroTrustSecurityService.invalidateAllUserSessions(userId, reason);

        } catch (Exception e) {
            log.error("[ZeroTrust] Error invalidating all sessions for user: {}", userId, e);
        }
    }


}