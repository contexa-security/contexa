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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.properties.VectorStoreRetryProperties;
import io.contexa.contexacore.std.rag.service.InMemoryFailedDocumentSink;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * QF-25 (b), R12: the decision document of an enforced request is stored by the learning executor. When that executor
 * is saturated, the enforcement's commit, which runs under the request's lock, must not store the document itself
 * (embedding and store, up to the store timeout): the document waits for the store retry instead and is not lost.
 */
class LearningStoreSaturationTest {

    private ThreadPoolExecutor learningExecutor;
    private ExecutorService vectorExecutor;
    private UnifiedVectorService vectorService;
    private VectorStore vectorStore;
    private final CountDownLatch release = new CountDownLatch(1);

    @BeforeEach
    void saturateTheLearningExecutor() throws InterruptedException {
        learningExecutor = (ThreadPoolExecutor) new CoreAutonomousAutoConfiguration()
                .securityLearningPostProcessExecutor();
        CountDownLatch started = new CountDownLatch(learningExecutor.getMaximumPoolSize());
        Runnable blocker = () -> {
            started.countDown();
            awaitRelease();
        };
        for (int i = 0; i < learningExecutor.getCorePoolSize(); i++) {
            learningExecutor.execute(blocker);
        }
        while (learningExecutor.getQueue().remainingCapacity() > 0) {
            learningExecutor.execute(() -> { });
        }
        for (int i = learningExecutor.getCorePoolSize(); i < learningExecutor.getMaximumPoolSize(); i++) {
            learningExecutor.execute(blocker);
        }
        assertThat(started.await(5, TimeUnit.SECONDS)).as("every learning thread is busy").isTrue();

        vectorStore = mock(VectorStore.class);
        vectorExecutor = Executors.newSingleThreadExecutor();
        VectorStoreRetryProperties retry = new VectorStoreRetryProperties();
        retry.setInitialDelay(Duration.ofHours(1));
        vectorService = new UnifiedVectorService(new PgVectorStoreProperties(), mock(VectorStoreCacheLayer.class),
                vectorStore, vectorExecutor, PastRecordQuery.unavailable(), retry, new InMemoryFailedDocumentSink(10));
    }

    @AfterEach
    void releaseTheLearningExecutor() throws Exception {
        release.countDown();
        learningExecutor.shutdown();
        learningExecutor.awaitTermination(10, TimeUnit.SECONDS);
        vectorService.destroy();
        vectorExecutor.shutdownNow();
    }

    @Test
    void aSaturatedExecutorLeavesTheDocumentToTheRetryInsteadOfStoringItInTheCommit() {
        SecurityLearningService learning = new SecurityLearningService(null,
                new SecurityDecisionPostProcessor(null, vectorService), learningExecutor);
        ContextObservationRecorder recorder = new ContextObservationRecorder(mock(SecurityContextDataStore.class));
        learning.setContextObservationRecorder(recorder);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("saturated-1")
                .userId("alice")
                .timestamp(Instant.parse("2026-10-30T10:00:00Z"))
                .build();
        event.addMetadata("requestPath", "/api/reports/1");

        learning.postProcessDecision(event, SecurityDecision.builder().action(ZeroTrustAction.ALLOW)
                .riskScore(0.1).confidence(1.0).build());
        recorder.commit(event, "ALLOW", true);

        verify(vectorStore, never()).add(any());
        assertThat(vectorService.storeFailureStats().pending()).as("the document waits for the retry").isEqualTo(1);
        assertThat(vectorService.storeFailureStats().failed()).as("no store failed").isZero();
        assertThat(vectorService.storeFailureStats().deferred()).as("counted as deferred").isEqualTo(1);
    }

    private void awaitRelease() {
        try {
            release.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
