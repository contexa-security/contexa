/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.springbootstartercontexa;

import io.contexa.autoconfigure.core.infra.StandaloneAutoConfigurationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.sql.init.SqlInitializationAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.annotation.ImportCandidates;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Environment-level isolation contract: adding the starter without {@code @EnableAISecurity} must not change
 * the host application's configuration, and a host application's own Redis/Kafka setup must survive the
 * standalone infrastructure filter once the platform is active.
 */
class DependencyOnlyEnvironmentIsolationIntegrationTest {

    private static final String BOOT_REDIS = "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration";
    private static final String BOOT_REDIS_REACTIVE =
            "org.springframework.boot.autoconfigure.data.redis.RedisReactiveAutoConfiguration";
    private static final String BOOT_KAFKA = "org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration";
    private static final String CONTEXA_REDIS = "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration";
    private static final String CONTEXA_STATE_MACHINE_REDIS = "io.contexa.contexaidentity.config.ZeroTrustRedisConfig";

    @Test
    void dependencyOnlyApplicationReceivesNoNonContexaDefaults() {
        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(DependencyOnlyApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "spring.main.banner-mode=off",
                        "contexa.vectorstore.pgvector.dimensions=1536")
                .run()) {
            ConfigurableEnvironment environment = context.getEnvironment();

            assertThat(environment.getProperty("spring.application.name")).isNull();
            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isNull();
            assertThat(environment.containsProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isFalse();
            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isNull();
            assertThat(environment.getProperty("spring.ai.openai.embedding.options.model")).isNull();
            assertThat(environment.getProperty("management.metrics.enable.lettuce")).isNull();
            assertThat(Binder.get(environment)
                    .bind("management.metrics.enable", Bindable.mapOf(String.class, Boolean.class))
                    .isBound()).isFalse();
            assertThat(environment.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1536");

            environment.getPropertySources().addFirst(new MapPropertySource(
                    "contexaAiSecurityAnnotation", Map.of("contexa.ai.security.mode", "SANDBOX")));

            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isEqualTo("true");
            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("1536");
            assertThat(environment.getProperty("spring.ai.openai.embedding.options.model"))
                    .isEqualTo("text-embedding-3-small");
            assertThat(Binder.get(environment)
                    .bind("management.metrics.enable", Bindable.mapOf(String.class, Boolean.class))
                    .get()).containsEntry("lettuce", false);
        }
    }

    @Test
    void gatedDefaultsFollowTheEnvironmentReplacedByWebApplicationTypeBinding() {
        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(DependencyOnlyApplication.class)
                .properties(
                        "spring.main.banner-mode=off",
                        "spring.main.web-application-type=none")
                .run()) {
            ConfigurableEnvironment environment = context.getEnvironment();
            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isNull();

            environment.getPropertySources().addFirst(new MapPropertySource(
                    "contexaAiSecurityAnnotation", Map.of("contexa.ai.security.mode", "SANDBOX")));

            assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isEqualTo("true");
        }
    }

    @Test
    void standaloneFilterKeepsHostRedisAndKafkaAutoConfigurations() {
        String[] candidates = autoConfigurationCandidates();
        assertThat(candidates).contains(BOOT_REDIS, BOOT_REDIS_REACTIVE, BOOT_KAFKA,
                CONTEXA_REDIS, CONTEXA_STATE_MACHINE_REDIS);

        Map<String, Boolean> withoutHostInfrastructure = filter(candidates, Map.of());
        assertThat(withoutHostInfrastructure).containsEntry(BOOT_REDIS, false)
                .containsEntry(BOOT_REDIS_REACTIVE, false)
                .containsEntry(BOOT_KAFKA, false)
                .containsEntry(CONTEXA_REDIS, false)
                .containsEntry(CONTEXA_STATE_MACHINE_REDIS, false);

        Map<String, Boolean> withHostInfrastructure = filter(candidates, Map.of(
                "spring.data.redis.host", "redis.host.internal",
                "spring.kafka.bootstrap-servers[0]", "kafka.host.internal:9092"));
        assertThat(withHostInfrastructure).containsEntry(BOOT_REDIS, true)
                .containsEntry(BOOT_REDIS_REACTIVE, true)
                .containsEntry(BOOT_KAFKA, true)
                .containsEntry(CONTEXA_REDIS, false)
                .containsEntry(CONTEXA_STATE_MACHINE_REDIS, false);
    }

    private String[] autoConfigurationCandidates() {
        List<String> candidates = new ArrayList<>();
        ImportCandidates.load(AutoConfiguration.class, getClass().getClassLoader()).forEach(candidates::add);
        return candidates.toArray(new String[0]);
    }

    private Map<String, Boolean> filter(String[] candidates, Map<String, Object> hostProperties) {
        StandardEnvironment environment = new StandardEnvironment();
        Map<String, Object> properties = new LinkedHashMap<>(hostProperties);
        properties.put("contexa.ai.security.mode", "SANDBOX");
        properties.put("contexa.infrastructure.mode", "standalone");
        environment.getPropertySources().addFirst(new MapPropertySource("hostApplication", properties));
        ConfigurationPropertySources.attach(environment);

        StandaloneAutoConfigurationFilter filter = new StandaloneAutoConfigurationFilter();
        filter.setEnvironment(environment);
        boolean[] matches = filter.match(candidates, mock(AutoConfigurationMetadata.class));

        Map<String, Boolean> result = new LinkedHashMap<>();
        for (int i = 0; i < candidates.length; i++) {
            result.put(candidates[i], matches[i]);
        }
        return result;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = {
            DataSourceAutoConfiguration.class,
            DataSourceTransactionManagerAutoConfiguration.class,
            HibernateJpaAutoConfiguration.class,
            SqlInitializationAutoConfiguration.class
    })
    static class DependencyOnlyApplication {
    }
}
