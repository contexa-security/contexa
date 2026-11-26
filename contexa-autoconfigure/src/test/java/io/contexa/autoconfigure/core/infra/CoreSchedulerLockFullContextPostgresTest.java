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

import io.contexa.autoconfigure.core.scope.ContexaPackages;
import io.contexa.autoconfigure.core.scope.ContexaSchedulerLockAnnotationBeanPostProcessor;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.aop.Advisor;
import org.springframework.aop.framework.Advised;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's locks in an application Contexa runs in, on a real servlet container and a real PostgreSQL database
 * (R-9 of docs/agent/운영모드-정상화-구현계획.md): every bean of Contexa's with a {@code @SchedulerLock} method is
 * proxied with Contexa's lock in front, the lock provider is Contexa's by its name, and the application's lookups of a
 * lock provider find none. The application starts once, on a database of its own that is dropped afterwards.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@Timeout(600)
class CoreSchedulerLockFullContextPostgresTest {

    private static final int DIMENSIONS = 1024;

    private String database;
    private ConfigurableApplicationContext context;

    @BeforeAll
    void start() {
        database = "contexa_lockbeans_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(dataSource("postgres")).execute("create database " + database);
        context = new SpringApplicationBuilder(SandboxApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties("spring.main.banner-mode=off", "server.port=0",
                        "contexa.datasource.url=" + urlOf(database),
                        "contexa.datasource.username=" + System.getenv("CONTEXA_TEST_DB_USERNAME"),
                        "contexa.datasource.password=" + System.getenv("CONTEXA_TEST_DB_PASSWORD"),
                        "contexa.llm.selection.chat.mode=spring-primary",
                        "contexa.llm.selection.embedding.mode=spring-primary",
                        "contexa.security.zerotrust.mode=DISABLED")
                .run();
    }

    @AfterAll
    void stop() {
        if (context != null) {
            context.close();
        }
        if (database == null) {
            return;
        }
        JdbcTemplate admin = new JdbcTemplate(dataSource("postgres"));
        admin.queryForList("select pg_terminate_backend(pid) from pg_stat_activity where datname = ?", database);
        admin.execute("drop database if exists " + database);
    }

    @Test
    @DisplayName("Contexa가 기동한 앱에서 @SchedulerLock 메서드를 가진 Contexa 빈마다 Contexa 잠금이 맨 앞에 붙고, 앱의 타입 조회에는 잠금 제공자가 없다")
    void everyLockedBeanOfContexaTakesContexasLockFirst() {
        List<String> locked = new ArrayList<>();
        List<String> violations = new ArrayList<>();
        for (String name : context.getBeanDefinitionNames()) {
            if (!context.getBeanFactory().getBeanDefinition(name).isSingleton()) {
                continue;
            }
            Class<?> type = context.getBeanFactory().getType(name, false);
            Class<?> target = type != null ? ClassUtils.getUserClass(type) : null;
            if (target == null || !ContexaPackages.owns(target) || !hasLockedMethod(target)) {
                continue;
            }
            locked.add(name);
            Object bean = context.getBean(name);
            Advisor[] advisors = bean instanceof Advised advised ? advised.getAdvisors() : new Advisor[0];
            if (advisors.length == 0 || !advisors[0].getAdvice().getClass().getName()
                    .startsWith(ContexaSchedulerLockAnnotationBeanPostProcessor.class.getName())) {
                violations.add(name + " " + Arrays.stream(advisors).map(advisor -> advisor.getAdvice().getClass().getName())
                        .toList());
            }
        }
        System.out.println("CONTEXA BEANS WITH @SchedulerLock: " + locked);

        assertThat(locked).as("the beans of Contexa with a locked method in this application").isNotEmpty();
        assertThat(violations).as("a locked bean of Contexa without Contexa's lock in front").isEmpty();
        assertThat(context.containsBean(CoreSchedulerLockAutoConfiguration.LOCK_PROVIDER)).isTrue();
        assertThat(context.getBeanProvider(LockProvider.class).getIfAvailable())
                .as("the application's lookups of a lock provider").isNull();
    }

    private static boolean hasLockedMethod(Class<?> type) {
        return Arrays.stream(ReflectionUtils.getUniqueDeclaredMethods(type))
                .anyMatch(method -> AnnotatedElementUtils.hasAnnotation(method, SchedulerLock.class));
    }

    private static String urlOf(String name) {
        String url = System.getenv("CONTEXA_TEST_DB_URL");
        return url.substring(0, url.lastIndexOf('/') + 1) + name;
    }

    private static DriverManagerDataSource dataSource(String name) {
        return new DriverManagerDataSource(urlOf(name), System.getenv("CONTEXA_TEST_DB_USERNAME"),
                System.getenv("CONTEXA_TEST_DB_PASSWORD"));
    }

    /** An application that turned Contexa on and nothing else of its own. */
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class SandboxApplication {

        @Bean
        ChatModel silentChatModel() {
            return new SilentChatModel();
        }

        @Bean
        EmbeddingModel flatEmbeddingModel() {
            return new FlatEmbeddingModel();
        }
    }

    /** Zero trust is off here, so no model is asked anything: a model only has to exist for Contexa to start. */
    static final class SilentChatModel implements ChatModel {

        @Override
        public ChatResponse call(Prompt prompt) {
            return new ChatResponse(List.of(new Generation(new AssistantMessage("{}"))));
        }
    }

    static final class FlatEmbeddingModel implements EmbeddingModel {

        @Override
        public EmbeddingResponse call(EmbeddingRequest request) {
            List<Embedding> embeddings = new ArrayList<>();
            for (int index = 0; index < request.getInstructions().size(); index++) {
                embeddings.add(new Embedding(new float[DIMENSIONS], index));
            }
            return new EmbeddingResponse(embeddings);
        }

        @Override
        public float[] embed(Document document) {
            return new float[DIMENSIONS];
        }

        @Override
        public int dimensions() {
            return DIMENSIONS;
        }
    }
}
