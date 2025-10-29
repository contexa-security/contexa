package io.contexa.contexacore.infra.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.AuthContextProperties;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.std.strategy.LabExecutionStrategy;
import io.contexa.contexacore.infra.session.generator.HttpSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.RedisSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import io.contexa.contexacore.infra.session.impl.HttpSessionMfaRepository;
import io.contexa.contexacore.infra.session.impl.RedisMfaRepository;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MFA Repository 자동 설정 및 통합 관리 - 최종 완성판
 *
 * 핵심 기능:
 * - 환경 자동 감지 및 최적 Repository 선택
 * - Repository 헬스체킹 및 Fallback 지원
 * - 분산환경 대응 우선순위 관리
 * - 실시간 모니터링 및 통계 수집
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(AuthContextProperties.class)
public class MfaRepositoryAutoConfiguration {

    private final AuthContextProperties properties;
    private final ApplicationContext applicationContext;
    private final Environment environment;
    private final RedisEventPublisher eventPublisher;
    private final RedisDistributedLockService lockService;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private final Map<String, AIStrategySessionRepository> repositoryCache = new ConcurrentHashMap<>();
    private final Map<String, Boolean> repositoryHealthStatus = new ConcurrentHashMap<>();

    @PostConstruct
    public void initialize() {
        log.info("=== MFA Repository Auto Configuration Initialized ===");
        log.info("Storage Type: {}", properties.getMfa().getSessionStorageType());
        log.info("Auto Select: {}", properties.getMfa().isAutoSelectRepository());
        log.info("Priority: {}", properties.getMfa().getRepositoryPriority());
        log.info("Fallback: {}", properties.getMfa().getFallbackRepositoryType());
        log.info("Environment: {}", detectEnvironmentType());
        log.info("======================================================");
    }

    /**
     * 메인 Repository Bean - 최종 완성판
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(MfaSessionRepository.class)
    public AIStrategySessionRepository aiStrategySessionRepository() {
        if (properties.getMfa().isAutoSelectRepository()) {
            return createAutoSelectedRepository();
        } else {
            return createConfiguredRepository();
        }
    }

    @Bean
    public SessionIdGenerator sessionIdGenerator() {
            return new HttpSessionIdGenerator();
    }

    /**
     * Repository 자동 선택 로직
     */
    private AIStrategySessionRepository createAutoSelectedRepository() {
        log.info("Auto-selecting optimal MFA Repository based on environment: {}", detectEnvironmentType());

        String[] priorities = properties.getMfa().getRepositoryPriority().split(",");

        for (String repositoryType : priorities) {
            String trimmedType = repositoryType.trim().toLowerCase();

            try {
                AIStrategySessionRepository repository = createRepositoryByType(trimmedType);
                if (repository != null && isRepositoryHealthy(repository)) {
                    log.info("Auto-selected MFA Repository: {} ({})",
                            repository.getRepositoryType(), repository.getClass().getSimpleName());
                    return wrapWithHealthChecking(repository);
                }
            } catch (Exception e) {
                log.warn("Failed to create repository type '{}': {}", trimmedType, e.getMessage());
            }
        }

        return createFallbackRepository();
    }

    /**
     * 설정된 Repository 생성
     */
    private AIStrategySessionRepository createConfiguredRepository() {
        String storageType = properties.getMfa().getSessionStorageType().toLowerCase();
        log.info("Creating configured MFA Repository: {}", storageType);

        try {
            AIStrategySessionRepository repository = createRepositoryByType(storageType);
            if (repository != null) {
                return wrapWithHealthChecking(repository);
            }
        } catch (Exception e) {
            log.error("Failed to create configured repository '{}': {}", storageType, e.getMessage());
        }

        log.warn("Falling back to fallback repository due to configuration failure");
        return createFallbackRepository();
    }

    /**
     * 타입별 Repository 생성
     */
    private AIStrategySessionRepository createRepositoryByType(String type) {
        return repositoryCache.computeIfAbsent(type, t -> {
            return switch (t) {
                case "redis" -> createAIRedisRepository();
//                case "memory" -> createInMemoryRepository();
//                case "http-session" -> createHttpSessionRepository();
                case "auto" -> createAutoSelectedRepository();
                default -> {
                    log.warn("Unknown repository type: {}", t);
                    yield null;
                }
            };
        });
    }

    /**
     * Redis Repository 생성
     */
    private MfaSessionRepository createRedisRepository() {
        try {
            StringRedisTemplate redisTemplate = applicationContext.getBean(StringRedisTemplate.class);

            // Redis 연결 테스트
            redisTemplate.opsForValue().get("__health_check__");

            RedisMfaRepository repository = new RedisMfaRepository(redisTemplate, new RedisSessionIdGenerator(redisTemplate));
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            log.info("Redis MFA Repository created successfully");
            return repository;

        } catch (Exception e) {
            log.warn("Failed to create Redis repository: {}", e.getMessage());
            return null;
        }
    }

    private AIStrategySessionRepository createAIRedisRepository() {
        try {
            redisTemplate.opsForValue().get("__health_check__");

            RedisAIStrategySessionRepository repository = new RedisAIStrategySessionRepository(
                    redisTemplate,
                    new RedisSessionIdGenerator(redisTemplate),
                    lockService,
                    eventPublisher,
                    objectMapper
            );
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            log.info("Redis MFA Repository created successfully");
            return repository;

        } catch (Exception e) {
            log.warn("Failed to create Redis repository: {}", e.getMessage());
            return null;
        }
    }

    /**
     * InMemory Repository 생성
     */
    /*private AIStrategySessionRepository createInMemoryRepository() {
        try {
            InMemoryMfaRepository repository = new InMemoryMfaRepository(new InMemorySessionIdGenerator());
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            log.info("InMemory MFA Repository created successfully");
            return repository;

        } catch (Exception e) {
            log.warn("Failed to create InMemory repository: {}", e.getMessage());
            return null;
        }
    }*/

    /**
     * HttpSession Repository 생성
     */
    private MfaSessionRepository createHttpSessionRepository() {
        try {
            HttpSessionMfaRepository repository = new HttpSessionMfaRepository(new HttpSessionIdGenerator());
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            log.info("HttpSession MFA Repository created successfully");
            return repository;

        } catch (Exception e) {
            log.warn("Failed to create HttpSession repository: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Fallback Repository 생성
     */
    private AIStrategySessionRepository createFallbackRepository() {
        String fallbackType = properties.getMfa().getFallbackRepositoryType().toLowerCase();
        log.info("Creating fallback MFA Repository: {}", fallbackType);

        AIStrategySessionRepository repository = createRepositoryByType(fallbackType);
        if (repository != null) {
            log.info("Fallback repository created: {}", repository.getRepositoryType());
            return wrapWithHealthChecking(repository);
        }

        log.warn("All repository creation failed, using final fallback: HttpSession");
        return createAIRedisRepository();
    }

    /**
     * Repository 헬스체크
     */
    private boolean isRepositoryHealthy(MfaSessionRepository repository) {
        String repositoryType = repository.getRepositoryType();

        return repositoryHealthStatus.computeIfAbsent(repositoryType, type -> {
            try {
                boolean isHealthy = performHealthCheck(repository);

                if (isHealthy && repository.supportsDistributedSync()) {
                    isHealthy = verifyDistributedSyncCapability(repository);
                }

                log.debug("Repository {} health check: {}", repositoryType, isHealthy ? "HEALTHY" : "UNHEALTHY");
                return isHealthy;

            } catch (Exception e) {
                log.warn("Health check failed for repository {}: {}", repositoryType, e.getMessage());
                return false;
            }
        });
    }

    /**
     * 기본 헬스체크 수행
     */
    private boolean performHealthCheck(MfaSessionRepository repository) {
        try {
            MfaSessionRepository.SessionStats stats = repository.getSessionStats();
            return stats != null;

        } catch (Exception e) {
            log.debug("Basic health check failed for {}: {}", repository.getRepositoryType(), e.getMessage());
            return false;
        }
    }

    /**
     * 분산 동기화 능력 검증
     */
    private boolean verifyDistributedSyncCapability(MfaSessionRepository repository) {
        try {
            String testId = UUID.randomUUID().toString();
            return repository.isSessionIdUnique(testId);

        } catch (Exception e) {
            log.debug("Distributed sync verification failed for {}: {}",
                    repository.getRepositoryType(), e.getMessage());
            return false;
        }
    }

    /**
     * Repository를 헬스체킹으로 감싸기
     */
    private AIStrategySessionRepository wrapWithHealthChecking(MfaSessionRepository repository) {
        return new HealthCheckingRepositoryWrapper(repository, this);
    }

    /**
     * 환경 타입 감지
     */
    private String detectEnvironmentType() {
        if (isClusterEnvironment()) {
            return "CLUSTER";
        } else if (isDevelopmentEnvironment()) {
            return "DEVELOPMENT";
        } else {
            return "SINGLE_SERVER";
        }
    }

    /**
     * 클러스터 환경 여부 판단
     */
    private boolean isClusterEnvironment() {
        boolean hasSpringCloud = environment.containsProperty("spring.cloud.kubernetes.enabled") ||
                environment.containsProperty("spring.cloud.consul.enabled") ||
                environment.containsProperty("eureka.client.enabled");

        boolean hasRedis = environment.containsProperty("spring.redis.host") ||
                environment.containsProperty("spring.redis.cluster.nodes");

        boolean hasLoadBalancer = environment.containsProperty("server.forward-headers-strategy");

        return hasSpringCloud || (hasRedis && hasLoadBalancer);
    }

    /**
     * 개발 환경 여부 판단
     */
    private boolean isDevelopmentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.stream(activeProfiles)
                .anyMatch(profile -> profile.contains("dev") ||
                        profile.contains("test") ||
                        profile.contains("local"));
    }

/**
 * 헬스체킹 기능을 추가한 Repository 래퍼 - 최종 완성판
 */
@Slf4j
static class HealthCheckingRepositoryWrapper implements AIStrategySessionRepository {

    private final MfaSessionRepository delegate;
    private final MfaRepositoryAutoConfiguration config;
    private volatile boolean isHealthy = true;
    private long lastHealthCheck = 0;
    private static final long HEALTH_CHECK_INTERVAL = 60_000; // 1분

    public HealthCheckingRepositoryWrapper(MfaSessionRepository delegate,
                                           MfaRepositoryAutoConfiguration config) {
        this.delegate = delegate;
        this.config = config;
    }

    @Override
    public void storeSession(String sessionId, HttpServletRequest request,
                             HttpServletResponse response) {
        checkHealthIfNeeded();
        delegate.storeSession(sessionId, request, response);
    }

    @Override
    public String getSessionId(HttpServletRequest request) {
        checkHealthIfNeeded();
        return delegate.getSessionId(request);
    }

    @Override
    public void removeSession(String sessionId, HttpServletRequest request,
                              HttpServletResponse response) {
        delegate.removeSession(sessionId, request, response);
    }

    @Override
    public void refreshSession(String sessionId) {
        delegate.refreshSession(sessionId);
    }

    @Override
    public boolean existsSession(String sessionId) {
        checkHealthIfNeeded();
        return delegate.existsSession(sessionId);
    }

    @Override
    public void setSessionTimeout(java.time.Duration timeout) {
        delegate.setSessionTimeout(timeout);
    }

    @Override
    public String getRepositoryType() {
        return delegate.getRepositoryType() + "_HEALTH_MONITORED";
    }

    @Override
    public String generateUniqueSessionId(String baseId, HttpServletRequest request) {
        checkHealthIfNeeded();
        return delegate.generateUniqueSessionId(baseId, request);
    }

    @Override
    public boolean isSessionIdUnique(String sessionId) {
        return delegate.isSessionIdUnique(sessionId);
    }

    @Override
    public String resolveSessionIdCollision(String originalId, HttpServletRequest request,
                                            int maxAttempts) {
        return delegate.resolveSessionIdCollision(originalId, request, maxAttempts);
    }

    @Override
    public boolean isValidSessionIdFormat(String sessionId) {
        return delegate.isValidSessionIdFormat(sessionId);
    }

    @Override
    public boolean supportsDistributedSync() {
        return delegate.supportsDistributedSync();
    }

    @Override
    public SessionStats getSessionStats() {
        checkHealthIfNeeded();
        SessionStats delegateStats = delegate.getSessionStats();

        return new SessionStats(
                delegateStats.getActiveSessions(),
                delegateStats.getTotalSessionsCreated(),
                delegateStats.getSessionCollisions(),
                delegateStats.getAverageSessionDuration(),
                getRepositoryType() + (isHealthy ? "_✅" : "_")
        );
    }

    private void checkHealthIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - lastHealthCheck > HEALTH_CHECK_INTERVAL) {
            try {
                SessionStats stats = delegate.getSessionStats();
                isHealthy = (stats != null);
                lastHealthCheck = now;

                if (!isHealthy) {
                    log.warn("Repository {} failed health check", delegate.getRepositoryType());
                }
            } catch (Exception e) {
                isHealthy = false;
                lastHealthCheck = now;
                log.warn("Repository {} health check exception: {}", delegate.getRepositoryType(), e.getMessage());
            }
        }
    }

    @Override
    public String createStrategySession(LabExecutionStrategy strategy, Map<String, Object> context, HttpServletRequest request, HttpServletResponse response) {
        return "";
    }

    @Override
    public void updateStrategyState(String sessionId, AIStrategyExecutionPhase phase, Map<String, Object> phaseData) {

    }

    @Override
    public AIStrategySessionState getStrategyState(String sessionId) {
        return null;
    }

    @Override
    public void storeLabAllocation(String sessionId, String labType, String nodeId, Map<String, Object> allocation) {

    }

    @Override
    public AILabAllocation getLabAllocation(String sessionId) {
        return null;
    }

    @Override
    public void recordExecutionMetrics(String sessionId, AIExecutionMetrics metrics) {

    }

    @Override
    public List<String> getActiveStrategySessions() {
        return List.of();
    }

    @Override
    public List<String> getActiveSessionsByNode(String nodeId) {
        return List.of();
    }

    @Override
    public boolean migrateStrategySession(String sessionId, String fromNodeId, String toNodeId) {
        return false;
    }

    @Override
    public void storeExecutionResult(String sessionId, AIExecutionResult result) {

    }

    @Override
    public AIExecutionResult getExecutionResult(String sessionId) {
        return null;
    }

    @Override
    public void syncSessionAcrossNodes(String sessionId) {

    }

    @Override
    public AIStrategySessionStats getAIStrategyStats() {
        return null;
    }
}
}

