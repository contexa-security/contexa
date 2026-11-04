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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.zerotrust.stepup.HostOwnedStepUpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Spring Security's {@link JdbcOneTimeTokenService} starts a scheduler thread (the clean-up of expired tokens, not a daemon) when it is
 * built and stops it only in {@code destroy()}. Contexa builds two of them itself, outside of the application context's lifecycle
 * (the e-mail service's delegate, the step-up code service): left running, the thread outlives a closed or a failed application context,
 * and the JVM of the application that embeds Contexa does not end. Found by the hostile host (a start-up that failed after these beans were built).
 */
class OneTimeTokenSchedulerLifecycleTest {

    private static final String SCHEDULER_THREADS = "spring-one-time-tokens-";

    private static long schedulerThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.isAlive() && t.getName().startsWith(SCHEDULER_THREADS))
                .count();
    }

    private static boolean awaitSchedulerThreads(long expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (schedulerThreads() != expected && System.nanoTime() < deadline) {
            Thread.sleep(25);
        }
        return schedulerThreads() == expected;
    }

    @Test
    @DisplayName("control: a one-time token service built outside of the context keeps its thread until it is destroyed")
    void anUnmanagedServiceKeepsItsSchedulerThread() throws Exception {
        long before = schedulerThreads();
        JdbcOneTimeTokenService unmanaged = new JdbcOneTimeTokenService(mock(JdbcOperations.class));
        try {
            assertThat(awaitSchedulerThreads(before + 1)).as("the service starts a scheduler thread when it is built").isTrue();
            AnnotationConfigApplicationContext unrelated = new AnnotationConfigApplicationContext();
            unrelated.refresh();
            unrelated.close();
            assertThat(schedulerThreads()).as("closing a context does not stop a service it does not manage").isEqualTo(before + 1);
        } finally {
            unmanaged.destroy();
        }
        assertThat(awaitSchedulerThreads(before)).as("destroy() stops it").isTrue();
    }

    @Test
    @DisplayName("the e-mail one-time token service stops the scheduler of its delegate when the context closes")
    void theEmailServiceStopsItsSchedulerWithTheContext() throws Exception {
        long before = schedulerThreads();
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean("emailService", EmailOneTimeTokenService.class, () -> new EmailOneTimeTokenService(
                mock(EmailService.class), mock(JdbcTemplate.class), new TransactionTemplate(), mock(AuthContextProperties.class), false));
        context.refresh();
        try {
            assertThat(awaitSchedulerThreads(before + 1)).as("the delegate runs one scheduler").isTrue();
        } finally {
            context.close();
        }
        assertThat(awaitSchedulerThreads(before)).as("the scheduler is stopped with the context").isTrue();
    }

    @Test
    @DisplayName("the host-owned step-up service stops the scheduler of its code service when the context closes")
    void theStepUpServiceStopsItsCodeServiceWithTheContext() throws Exception {
        long before = schedulerThreads();
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean("stepUp", HostOwnedStepUpService.class, () -> new HostOwnedStepUpService(
                null, null, null, "contexa.invalid", null, new JdbcOneTimeTokenService(mock(JdbcOperations.class)),
                null, null, null, null, null, null));
        context.refresh();
        try {
            assertThat(awaitSchedulerThreads(before + 1)).as("the code service runs one scheduler").isTrue();
        } finally {
            context.close();
        }
        assertThat(awaitSchedulerThreads(before)).as("the scheduler is stopped with the context").isTrue();
    }

    @Test
    @DisplayName("a step-up service without a code service closes without error")
    void aStepUpServiceWithoutCodesClosesCleanly() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean("stepUp", HostOwnedStepUpService.class, () -> new HostOwnedStepUpService(
                null, null, null, "contexa.invalid", null, null, null, null, null, null, null, null));
        context.refresh();
        context.close();
        assertThat(context.isActive()).isFalse();
    }
}
