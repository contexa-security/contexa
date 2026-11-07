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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.service.NewContextDecisionLimit.Kind;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * A person may ask for a few decisions of a new context in a short window; past them the model is not asked, and the
 * fact is reported once a minute.
 */
class NewContextDecisionLimitTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);

    private NewContextDecisionLimit limit(int decisions, Duration window) {
        SecurityZeroTrustProperties.NewContextLimit settings = new SecurityZeroTrustProperties.NewContextLimit();
        settings.setDecisions(decisions);
        settings.setWindow(window);
        return new NewContextDecisionLimit(settings, audit, clock);
    }

    private static int taken(NewContextDecisionLimit limit, String key, Kind kind, int times) {
        int taken = 0;
        for (int i = 0; i < times; i++) {
            if (limit.take(key, kind)) {
                taken++;
            }
        }
        return taken;
    }

    @Test
    @DisplayName("the default lets a person ask for six decisions of a new context a minute")
    void theDefaultIsSixAMinute() {
        SecurityZeroTrustProperties.NewContextLimit settings = new SecurityZeroTrustProperties.NewContextLimit();
        assertThat(settings.getDecisions()).isEqualTo(6);
        assertThat(settings.getWindow()).isEqualTo(Duration.ofMinutes(1));
        assertThat(new SecurityZeroTrustProperties().getAnalysis().getNewContextLimit()).isNotNull();

        NewContextDecisionLimit limit = new NewContextDecisionLimit(settings, audit, clock);

        assertThat(taken(limit, "alice", Kind.CHANGED_CONTEXT, 20)).isEqualTo(6);
    }

    @Test
    @DisplayName("each person counts for themselves")
    void eachPersonCountsForThemselves() {
        NewContextDecisionLimit limit = limit(2, Duration.ofMinutes(1));

        assertThat(taken(limit, "alice", Kind.CHANGED_CONTEXT, 5)).isEqualTo(2);

        assertThat(taken(limit, "bob", Kind.CHANGED_CONTEXT, 5)).isEqualTo(2);
        assertThat(taken(limit, "console::alice", Kind.CHANGED_CONTEXT, 5)).isEqualTo(2);
    }

    @Test
    @DisplayName("the window slides: a decision leaves it a window after it was taken, and refusals take no place")
    void theWindowSlides() {
        NewContextDecisionLimit limit = limit(2, Duration.ofMinutes(1));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isTrue();
        clock.advance(Duration.ofSeconds(30));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isTrue();
        assertThat(taken(limit, "alice", Kind.CHANGED_CONTEXT, 10)).isZero();

        clock.advance(Duration.ofSeconds(31));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).as("the first left the window").isTrue();
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).as("the second is still in it").isFalse();

        clock.advance(Duration.ofSeconds(30));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isTrue();
    }

    @Test
    @DisplayName("decisions of 0 or less set no limit")
    void noLimit() {
        assertThat(taken(limit(0, Duration.ofMinutes(1)), "alice", Kind.CHANGED_CONTEXT, 50)).isEqualTo(50);
        assertThat(taken(limit(-1, Duration.ofMinutes(1)), "alice", Kind.CHANGED_CONTEXT, 50)).isEqualTo(50);
        verify(audit, never()).recordAsync(any());
        verify(audit, never()).recordSync(any());
    }

    @Test
    @DisplayName("a window that is not positive reads as one minute")
    void aWindowThatIsNotPositiveIsAMinute() {
        NewContextDecisionLimit limit = limit(1, Duration.ZERO);
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isTrue();
        clock.advance(Duration.ofSeconds(59));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isFalse();
        clock.advance(Duration.ofSeconds(2));
        assertThat(limit.take("alice", Kind.CHANGED_CONTEXT)).isTrue();
    }

    @Test
    @DisplayName("reaching the limit is audited once a minute for the person, with what asked")
    void reachingTheLimitIsAuditedOnceAMinute() {
        NewContextDecisionLimit limit = limit(1, Duration.ofMinutes(1));
        limit.take("alice", Kind.CHANGED_CONTEXT);

        taken(limit, "alice", Kind.CHANGED_CONTEXT, 30);
        taken(limit, "alice", Kind.CHANGED_CONTEXT, 30);

        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getEventCategory()).isEqualTo(AuditEventCategory.DECISION_LIMIT_REACHED);
        assertThat(record.getValue().getPrincipalName()).isEqualTo("alice");
        assertThat(record.getValue().getDetails()).containsEntry("kind", "CHANGED_CONTEXT")
                .containsEntry("decisions", 1).containsEntry("windowSeconds", 60L);

        clock.advance(Duration.ofSeconds(61));
        limit.take("alice", Kind.CHANGED_CONTEXT);
        taken(limit, "alice", Kind.CHANGED_CONTEXT, 5);
        verify(audit, times(2)).recordAsync(any());

        limit.take("bob", Kind.CHANGED_CONTEXT);
        limit.take("bob", Kind.CHANGED_CONTEXT);
        verify(audit, times(3)).recordAsync(any());
    }

    @Test
    @DisplayName("requests at once take no more than the limit")
    void requestsAtOnceTakeNoMoreThanTheLimit() throws Exception {
        NewContextDecisionLimit limit = limit(6, Duration.ofMinutes(1));
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> answers = new ArrayList<>();
        try {
            for (int i = 0; i < 200; i++) {
                answers.add(pool.submit(() -> {
                    start.await();
                    return limit.take("alice", Kind.CHANGED_CONTEXT);
                }));
            }
            start.countDown();
            int granted = 0;
            for (Future<Boolean> answer : answers) {
                if (answer.get(10, TimeUnit.SECONDS)) {
                    granted++;
                }
            }
            assertThat(granted).isEqualTo(6);
        } finally {
            pool.shutdownNow();
        }
    }
}
