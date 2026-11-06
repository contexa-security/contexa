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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.RestrictionRestorer;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * On a real Spring Boot start with a real web server: the restrictions are brought under the keys of the application's
 * name before the server is started (and so before it takes a request).
 */
class RestrictionRestorerStartOrderTest {

    private static final AtomicInteger SEQUENCE = new AtomicInteger();
    private static volatile int restoredAt;
    private static volatile int serverStartedAt;

    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration(ServletWebServerFactoryAutoConfiguration.class)
    static class Application {

        @Bean
        RestrictionRestorer restorer() {
            ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
            when(actions.restoreBlockedFlag("alice")).thenAnswer(call -> {
                restoredAt = SEQUENCE.incrementAndGet();
                return true;
            });
            IBlockedUserRecorder recorder = mock(IBlockedUserRecorder.class);
            when(recorder.blocksInForce()).thenReturn(List.of("alice"));
            return new RestrictionRestorer(() -> actions, () -> recorder, () -> mock(SecurityContextDataStore.class));
        }

        @Bean
        ApplicationListener<WebServerInitializedEvent> serverStarted() {
            return event -> serverStartedAt = SEQUENCE.incrementAndGet();
        }
    }

    @BeforeEach
    void nothingHasHappenedYet() {
        SEQUENCE.set(0);
        restoredAt = 0;
        serverStartedAt = 0;
    }

    @Test
    @DisplayName("the blocks are written before the web server is started")
    void theBlocksAreWrittenBeforeTheWebServerStarts() {
        // The name comes from spring.application.name, bound at the start of the application as in production.
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("");
             ConfigurableApplicationContext context = new SpringApplicationBuilder(Application.class)
                     .web(WebApplicationType.SERVLET)
                     .properties("spring.application.name=shop", "server.port=0", "spring.main.banner-mode=off").run()) {
            assertThat(ApplicationNamespace.identifier()).isEqualTo("shop");
            assertThat(context.isRunning()).isTrue();
        }

        assertThat(restoredAt).as("the block was written").isPositive();
        assertThat(serverStartedAt).as("the web server was started").isPositive();
        assertThat(restoredAt).isLessThan(serverStartedAt);
    }

    @Test
    @DisplayName("an application without a name writes the blocks before the web server is started too")
    void anApplicationWithoutANameWritesTheBlocksBeforeTheWebServerStarts() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("");
             ConfigurableApplicationContext context = new SpringApplicationBuilder(Application.class)
                     .web(WebApplicationType.SERVLET)
                     .properties("server.port=0", "spring.main.banner-mode=off").run()) {
            assertThat(ApplicationNamespace.isNamed()).isFalse();
            assertThat(context.isRunning()).isTrue();
        }

        assertThat(restoredAt).as("the block was written").isPositive();
        assertThat(serverStartedAt).as("the web server was started").isPositive();
        assertThat(restoredAt).isLessThan(serverStartedAt);
    }
}
