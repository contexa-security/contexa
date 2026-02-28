package io.contexa.autoconfigure.core.infra;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

/**
 * Excludes Redis/Kafka/Redisson auto-configurations in standalone mode.
 * When contexa.infrastructure.mode=standalone (default), Spring Boot auto-configurations
 * that attempt to connect to Redis/Kafka servers are excluded.
 */
public class StandaloneInfrastructurePostProcessor implements EnvironmentPostProcessor {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";
    private static final String EXCLUDE_PROPERTY = "spring.autoconfigure.exclude";

    private static final String[] STANDALONE_EXCLUDES = {
            "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
            "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration",
            "org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration",
            "org.redisson.spring.starter.RedissonAutoConfigurationV2",
            "org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration",
            "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
    };

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String mode = environment.getProperty(MODE_PROPERTY, "standalone");
        if (!"standalone".equalsIgnoreCase(mode)) {
            return;
        }

        String existing = environment.getProperty(EXCLUDE_PROPERTY, "");
        StringBuilder excludes = new StringBuilder(existing);

        for (String exclude : STANDALONE_EXCLUDES) {
            if (!existing.contains(exclude)) {
                if (excludes.length() > 0) {
                    excludes.append(",");
                }
                excludes.append(exclude);
            }
        }

        Map<String, Object> properties = new HashMap<>();
        properties.put(EXCLUDE_PROPERTY, excludes.toString());
        environment.getPropertySources().addFirst(
                new MapPropertySource("standaloneInfrastructureExcludes", properties));
    }
}
