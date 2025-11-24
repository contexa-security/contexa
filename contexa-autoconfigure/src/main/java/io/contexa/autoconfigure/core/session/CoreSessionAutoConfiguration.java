package io.contexa.autoconfigure.core.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.AuthContextProperties;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.infra.session.AIStrategySessionRepository;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.RedisAIStrategySessionRepository;
import io.contexa.contexacore.infra.session.generator.HttpSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.RedisSessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import io.contexa.contexacore.infra.session.impl.HttpSessionMfaRepository;
import io.contexa.contexacore.infra.session.impl.RedisMfaRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Arrays;
import java.util.Map;
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
@AutoConfiguration
@AutoConfigureAfter(name = "io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration")
@RequiredArgsConstructor
@EnableConfigurationProperties(AuthContextProperties.class)
public class CoreSessionAutoConfiguration {

    private final AuthContextProperties properties;
    private final ApplicationContext applicationContext;
    private final Environment environment;
    private final RedisEventPublisher redisEventPublisher;
    private final RedisDistributedLockService lockService;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private final Map<String, AIStrategySessionRepository> repositoryCache = new ConcurrentHashMap<>();

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
     * MFA 인증 전용 Repository Bean - Primary
     * MfaRestAuthenticationFilter 등 순수 MFA 인증 컴포넌트에서 사용
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(MfaSessionRepository.class)
    public MfaSessionRepository mfaSessionRepository() {
        log.info("Creating PRIMARY MFA Repository for authentication");

        try {
            // Redis 연결 테스트
            redisTemplate.opsForValue().get("__health_check__");

            RedisMfaRepository repository = new RedisMfaRepository(
                    redisTemplate,
                    new RedisSessionIdGenerator(redisTemplate)
            );
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            log.info("✅ Primary MFA Repository created successfully: RedisMfaRepository");
            return repository;

        } catch (Exception e) {
            log.error("Failed to create primary MFA repository, falling back to HttpSession", e);

            // Fallback to HttpSession
            HttpSessionMfaRepository fallback = new HttpSessionMfaRepository(new HttpSessionIdGenerator());
            fallback.setSessionTimeout(properties.getMfa().getSessionTimeout());
            return fallback;
        }
    }

    /**
     * AI 전략 실행 전용 Repository Bean
     * AI 전략 실행 컴포넌트(DistributedStrategyExecutor 등)에서 사용
     * AI 기능이 활성화된 경우에만 생성
     */
    @Bean
    @ConditionalOnMissingBean
    public AIStrategySessionRepository aiStrategySessionRepository() {
        log.info("Creating AI Strategy Repository for AI execution");

        if (properties.getMfa().isAutoSelectRepository()) {
            return createAutoSelectedRepository();
        } else {
            return createConfiguredRepository();
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionIdGenerator sessionIdGenerator() {
            return new HttpSessionIdGenerator();
    }

    /**
     * Repository 자동 선택 로직
     */
    private AIStrategySessionRepository createAutoSelectedRepository() {
        log.info("Auto-selecting optimal AI Strategy Repository based on environment: {}", detectEnvironmentType());

        String[] priorities = properties.getMfa().getRepositoryPriority().split(",");

        for (String repositoryType : priorities) {
            String trimmedType = repositoryType.trim().toLowerCase();

            try {
                AIStrategySessionRepository repository = createRepositoryByType(trimmedType);
                if (repository != null) {
                    log.info("Auto-selected AI Strategy Repository: {}", repository.getClass().getSimpleName());
                    return repository;
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
        log.info("Creating configured AI Strategy Repository: {}", storageType);

        try {
            AIStrategySessionRepository repository = createRepositoryByType(storageType);
            if (repository != null) {
                return repository;
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
     * AI Redis Repository 생성
     */
    private AIStrategySessionRepository createAIRedisRepository() {
        try {
            redisTemplate.opsForValue().get("__health_check__");

            RedisAIStrategySessionRepository repository = new RedisAIStrategySessionRepository(
                    redisTemplate,
                    new RedisSessionIdGenerator(redisTemplate),
                    lockService,
                    redisEventPublisher,
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
        log.info("Creating fallback AI Strategy Repository: {}", fallbackType);

        AIStrategySessionRepository repository = createRepositoryByType(fallbackType);
        if (repository != null) {
            log.info("Fallback repository created: {}", repository.getClass().getSimpleName());
            return repository;
        }

        log.warn("All repository creation failed, using final fallback: Redis AI Repository");
        return createAIRedisRepository();
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
}
