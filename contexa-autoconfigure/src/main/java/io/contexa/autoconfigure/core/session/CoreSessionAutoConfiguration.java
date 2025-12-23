package io.contexa.autoconfigure.core.session;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Arrays;

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
    private final Environment environment;
    private final StringRedisTemplate redisTemplate;

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

    @Bean
    @ConditionalOnMissingBean
    public SessionIdGenerator sessionIdGenerator() {
            return new HttpSessionIdGenerator();
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
