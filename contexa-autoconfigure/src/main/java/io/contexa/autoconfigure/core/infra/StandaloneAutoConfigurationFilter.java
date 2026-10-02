/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core.infra;

import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

import java.util.List;
import java.util.Locale;

/**
 * Filters Redis/Kafka/Redisson auto-configurations in standalone mode.
 * Uses pattern-based matching instead of hardcoded FQCNs,
 * so Spring Boot version changes or new auto-configurations are handled automatically.
 *
 * <p>Contexa-owned ({@code io.contexa.*}) infrastructure auto-configurations are always excluded in
 * standalone mode. Third-party infrastructure auto-configurations (Spring Boot, Redisson, Spring Kafka)
 * are excluded only when the host application has not configured that infrastructure itself, so a host
 * application that uses its own Redis or Kafka keeps its auto-configuration.</p>
 */
public class StandaloneAutoConfigurationFilter implements AutoConfigurationImportFilter, EnvironmentAware {

    private static final String MODE_PROPERTY = "contexa.infrastructure.mode";

    private static final String REDIS_PATTERN = "redis";
    private static final String KAFKA_PATTERN = "kafka";
    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";
    private static final String CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION =
            "io.contexa.autoconfigure.core.ContexaOwnedDataSourceAutoConfiguration";

    /**
     * Connection keys that show the host application configured its own Redis. Redisson keys are included
     * because the Redisson starter also provides the Redis connection factory used by Spring Data Redis.
     */
    private static final List<String> APPLICATION_REDIS_PROPERTIES = List.of(
            "spring.data.redis.host",
            "spring.data.redis.port",
            "spring.data.redis.url",
            "spring.data.redis.cluster.nodes",
            "spring.data.redis.sentinel.nodes",
            "spring.redis.host",
            "spring.redis.port",
            "spring.redis.url",
            "spring.redis.cluster.nodes",
            "spring.redis.sentinel.nodes",
            "spring.data.redis.redisson.config",
            "spring.data.redis.redisson.file",
            "spring.redis.redisson.config",
            "spring.redis.redisson.file");

    /**
     * Connection keys that show the host application configured its own Kafka cluster.
     */
    private static final List<String> APPLICATION_KAFKA_PROPERTIES = List.of(
            "spring.kafka.bootstrap-servers",
            "spring.kafka.producer.bootstrap-servers",
            "spring.kafka.consumer.bootstrap-servers",
            "spring.kafka.admin.bootstrap-servers",
            "spring.kafka.streams.bootstrap-servers");

    private Environment environment;

    @Override
    public boolean[] match(String[] autoConfigurationClasses, AutoConfigurationMetadata metadata) {
        boolean isStandalone = "standalone".equalsIgnoreCase(
                environment.getProperty(MODE_PROPERTY, "standalone"));
        boolean contexaPlatformActive = isContexaPlatformActive();

        boolean[] result = new boolean[autoConfigurationClasses.length];
        for (int i = 0; i < autoConfigurationClasses.length; i++) {
            String autoConfigurationClass = autoConfigurationClasses[i];
            if (autoConfigurationClass == null) {
                result[i] = true;
                continue;
            }

            if (!contexaPlatformActive) {
                if (isContexaOwnedDataSourceAutoConfiguration(autoConfigurationClass)) {
                    result[i] = hasContexaOwnedDataSource();
                } else if (isContexaAutoConfiguration(autoConfigurationClass)) {
                    result[i] = false;
                } else if ("org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration".equals(autoConfigurationClass) ||
                           "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration".equals(autoConfigurationClass)) {
                    boolean hasUrl = environment.containsProperty("spring.datasource.url") || hasContexaOwnedDataSource();
                    boolean hasEmbedded = EmbeddedDatabaseConnection.get(getClass().getClassLoader()) != EmbeddedDatabaseConnection.NONE;
                    result[i] = hasUrl || hasEmbedded;
                } else {
                    result[i] = true;
                }
                continue;
            }

            result[i] = !isStandalone || !isExcludedInStandalone(autoConfigurationClass);
        }
        return result;
    }

    private boolean isExcludedInStandalone(String autoConfigurationClass) {
        String lowerName = autoConfigurationClass.toLowerCase(Locale.ROOT);
        boolean redisRelated = lowerName.contains(REDIS_PATTERN);
        boolean kafkaRelated = lowerName.contains(KAFKA_PATTERN);
        if (!redisRelated && !kafkaRelated) {
            return false;
        }
        if (isContexaAutoConfiguration(autoConfigurationClass)) {
            return true;
        }
        if (redisRelated && !hasAnyApplicationProperty(APPLICATION_REDIS_PROPERTIES)) {
            return true;
        }
        return kafkaRelated && !hasAnyApplicationProperty(APPLICATION_KAFKA_PROPERTIES);
    }

    private boolean hasAnyApplicationProperty(List<String> propertyNames) {
        for (String propertyName : propertyNames) {
            if (environment.containsProperty(propertyName)
                    || environment.containsProperty(propertyName + "[0]")) {
                return true;
            }
        }
        return false;
    }

    private boolean isContexaPlatformActive() {
        return ContexaPlatformActivation.isActive(environment);
    }

    private boolean isContexaAutoConfiguration(String autoConfigurationClass) {
        return autoConfigurationClass.startsWith(CONTEXA_PACKAGE_PREFIX);
    }

    private boolean isContexaOwnedDataSourceAutoConfiguration(String autoConfigurationClass) {
        return CONTEXA_OWNED_DATASOURCE_AUTO_CONFIGURATION.equals(autoConfigurationClass);
    }

    private boolean hasContexaOwnedDataSource() {
        return environment != null
                && environment.containsProperty("contexa.datasource.url")
                && environment.getProperty(
                        "contexa.datasource.isolation.contexa-owned-application",
                        Boolean.class,
                        false);
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }
}
