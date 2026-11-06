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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-91: the canonical context of a request is kept as its serialized bytes, tens of kilobytes with a long session, so
 * two thousand of them took a quarter of a small heap. What the cache keeps has a size limit; a context it does not
 * keep is resolved again, to the same context.
 */
class CanonicalContextCacheHeapTest {

    private static final int CONTEXT_CHARACTERS = 64 * 1024;

    @Test
    void theContextsKeptStayWithinTheBudgetWhateverTheirNumber() {
        CanonicalSecurityContextProvider provider = event -> Optional.of(context(event.getEventId()));
        SecurityDecisionPromptSections sections = sections(provider);
        long budget = SecurityDecisionPromptSections.defaultCanonicalContextBudgetBytes(Runtime.getRuntime().maxMemory());
        int contexts = Math.min(2_000, (int) (2 * budget / CONTEXT_CHARACTERS));

        for (int number = 0; number < contexts; number++) {
            sections.resolveCanonicalSecurityContext(event("event-" + number));
        }

        assertThat(sections.canonicalContextCacheBytes()).isPositive().isLessThanOrEqualTo(budget);
    }

    @Test
    void aContextTheCacheDidNotKeepIsResolvedAgainToTheSameContext() {
        AtomicInteger resolutions = new AtomicInteger();
        CanonicalSecurityContextProvider provider = event -> {
            resolutions.incrementAndGet();
            return Optional.of(context(event.getEventId()));
        };
        SecurityDecisionPromptSections sections = sections(provider);
        SecurityEvent event = event("event-kept");

        CanonicalSecurityContext first = sections.resolveCanonicalSecurityContext(event).orElseThrow();
        sections.clearCanonicalContextCache();
        CanonicalSecurityContext second = sections.resolveCanonicalSecurityContext(event).orElseThrow();

        assertThat(resolutions).hasValue(2);
        assertThat(second.getActor().getUserId()).isEqualTo(first.getActor().getUserId());
        assertThat(second.getAttributes()).isEqualTo(first.getAttributes());
    }

    @Test
    void theBudgetIsAThirtySecondOfTheHeapWithinItsBounds() {
        long mebibyte = 1024L * 1024;
        assertThat(SecurityDecisionPromptSections.defaultCanonicalContextBudgetBytes(128 * mebibyte))
                .isEqualTo(8 * mebibyte);
        assertThat(SecurityDecisionPromptSections.defaultCanonicalContextBudgetBytes(512 * mebibyte))
                .isEqualTo(16 * mebibyte);
        assertThat(SecurityDecisionPromptSections.defaultCanonicalContextBudgetBytes(2_048 * mebibyte))
                .isEqualTo(64 * mebibyte);
        assertThat(SecurityDecisionPromptSections.defaultCanonicalContextBudgetBytes(Long.MAX_VALUE))
                .isEqualTo(128 * mebibyte);
    }

    private static SecurityDecisionPromptSections sections(CanonicalSecurityContextProvider provider) {
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), new TieredStrategyProperties(), provider,
                new PromptContextComposer());
    }

    private static CanonicalSecurityContext context(String user) {
        return CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId(user).build())
                .attributes(Map.of("sessionDecisionHistory", "x".repeat(CONTEXT_CHARACTERS)))
                .build();
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder().eventId(eventId).build();
        event.addMetadata("requestId", eventId);
        return event;
    }
}
