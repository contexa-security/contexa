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

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(name = "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration")
@RequiredArgsConstructor
@EnableConfigurationProperties(AuthContextProperties.class)
public class CoreSessionAutoConfiguration {

    private final AuthContextProperties properties;
    private final Environment environment;
    private final StringRedisTemplate redisTemplate;

    @PostConstruct
    public void initialize() {
    }

    @Bean
    @Primary
    @ConditionalOnMissingBean(MfaSessionRepository.class)
    public MfaSessionRepository mfaSessionRepository() {

        try {

            redisTemplate.opsForValue().get("__health_check__");

            RedisMfaRepository repository = new RedisMfaRepository(
                    redisTemplate,
                    new RedisSessionIdGenerator(redisTemplate));
            repository.setSessionTimeout(properties.getMfa().getSessionTimeout());

            return repository;

        } catch (Exception e) {
            log.error("Failed to create primary MFA repository, falling back to HttpSession", e);

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

    private String detectEnvironmentType() {
        if (isClusterEnvironment()) {
            return "CLUSTER";
        } else if (isDevelopmentEnvironment()) {
            return "DEVELOPMENT";
        } else {
            return "SINGLE_SERVER";
        }
    }

    private boolean isClusterEnvironment() {
        boolean hasSpringCloud = environment.containsProperty("spring.cloud.kubernetes.enabled") ||
                environment.containsProperty("spring.cloud.consul.enabled") ||
                environment.containsProperty("eureka.client.enabled");

        boolean hasRedis = environment.containsProperty("spring.redis.host") ||
                environment.containsProperty("spring.redis.cluster.nodes");

        boolean hasLoadBalancer = environment.containsProperty("server.forward-headers-strategy");

        return hasSpringCloud || (hasRedis && hasLoadBalancer);
    }

    private boolean isDevelopmentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        return Arrays.stream(activeProfiles)
                .anyMatch(profile -> profile.contains("dev") ||
                        profile.contains("test") ||
                        profile.contains("local"));
    }
}
