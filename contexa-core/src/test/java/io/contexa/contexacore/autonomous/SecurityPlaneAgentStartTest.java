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
package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * PR-32: the agent started in a command line runner, after the web server was taking requests. What came in between was
 * refused three times within milliseconds and dropped, so the first user after a start passed without a decision.
 */
class SecurityPlaneAgentStartTest {

    private final SecurityMonitoringService monitor = mock(SecurityMonitoringService.class);

    private SecurityPlaneAgent agent(boolean autoStart) {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setAutoStart(autoStart);
        return new SecurityPlaneAgent(monitor, mock(SecurityContextDataStore.class), mock(CentralAuditFacade.class),
                mock(SecurityEventProcessor.class), properties, mock(Executor.class));
    }

    private SecurityMonitoringService.SecurityEventBatchProcessor batchProcessor() {
        ArgumentCaptor<SecurityMonitoringService.SecurityEventBatchProcessor> processor =
                ArgumentCaptor.forClass(SecurityMonitoringService.SecurityEventBatchProcessor.class);
        verify(monitor).setBatchProcessor(processor.capture());
        return processor.getValue();
    }

    private static List<SecurityEvent> firstEvent() {
        return List.of(SecurityEvent.builder().eventId("first").userId("first-user").build());
    }

    @RepeatedTest(20)
    @DisplayName("the agent takes events before the web server, a lifecycle bean, answers its first request")
    void theAgentRunsBeforeAnyLifecycleBeanStarts() {
        AtomicBoolean opened = new AtomicBoolean();
        AtomicReference<Throwable> refused = new AtomicReference<>();
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            SecurityPlaneAgent agent = agent(true);
            context.registerBean("securityPlaneAgent", SecurityPlaneAgent.class, () -> agent);
            context.registerBean("webServer", SmartLifecycle.class, () -> new WebServerStandIn(() -> {
                opened.set(true);
                try {
                    batchProcessor().processBatch(firstEvent());
                } catch (RuntimeException problem) {
                    refused.set(problem);
                }
            }));

            context.refresh();
        }

        assertThat(opened).isTrue();
        assertThat(refused.get()).as("the first event after the server opened").isNull();
    }

    @Test
    @DisplayName("an agent told not to start on its own stays stopped")
    void anAgentWithoutAutoStartStaysStopped() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            SecurityPlaneAgent agent = agent(false);
            context.registerBean("securityPlaneAgent", SecurityPlaneAgent.class, () -> agent);

            context.refresh();

            assertThatThrownBy(() -> batchProcessor().processBatch(firstEvent()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not running");
        }
    }

    /** Spring Boot's web server opens as a lifecycle bean, once every singleton exists. */
    private static final class WebServerStandIn implements SmartLifecycle {

        private final Runnable onStart;
        private boolean running;

        private WebServerStandIn(Runnable onStart) {
            this.onStart = onStart;
        }

        @Override
        public void start() {
            running = true;
            onStart.run();
        }

        @Override
        public void stop() {
            running = false;
        }

        @Override
        public boolean isRunning() {
            return running;
        }
    }
}
