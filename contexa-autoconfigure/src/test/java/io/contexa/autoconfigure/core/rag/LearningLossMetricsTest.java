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
package io.contexa.autoconfigure.core.rag;

import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BR-S5 (QF-12): the learnings that were worked out but could not be stored are published to the same registry as the
 * vector stores that failed, the retries and the stores left to the retry.
 */
class LearningLossMetricsTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreRAGAutoConfiguration.class))
            .withBean(AIStrategyRegistry.class, () -> mock(AIStrategyRegistry.class))
            .withBean(AuditLogger.class, () -> mock(AuditLogger.class))
            .withBean(DistributedLockService.class, () -> mock(DistributedLockService.class));

    @Test
    void theLostLearningsArePublishedNextToTheFailedStores() {
        BaselineLearningService baseline = mock(BaselineLearningService.class);
        when(baseline.lostLearnings()).thenReturn(2L);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withBean(BaselineLearningService.class, () -> baseline)
                .withBean(MeterRegistry.class, () -> registry)
                .run(context -> {
                    assertThat(registry.get("contexa.baseline.learning.lost").functionCounter().count()).isEqualTo(2.0);
                    assertThat(registry.find("contexa.vector.store.failed").functionCounter()).isNotNull();
                    assertThat(registry.find("contexa.vector.store.deferred").functionCounter()).isNotNull();
                });
    }

    @Test
    void withoutARegistryNothingIsBoundAndTheContextStarts() {
        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> mock(VectorStore.class))
                .withBean(BaselineLearningService.class, () -> mock(BaselineLearningService.class))
                .run(context -> assertThat(context).hasNotFailed());
    }
}
