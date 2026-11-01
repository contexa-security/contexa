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
package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Many requests of one user learned at the same moment (LQ-5, burst): every learning lands in the baseline and none is lost,
 * whichever thread comes first.
 */
class BaselineLearningConcurrencyTest {

    private static final String CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

    @Test
    void everyConcurrentLearningOfOneUserLandsInTheBaseline() throws Exception {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        SecurityZeroTrustProperties.BaselineSettings baseline = new SecurityZeroTrustProperties.BaselineSettings();
        SecurityZeroTrustProperties.BaselineSettings.LearningSettings learning =
                new SecurityZeroTrustProperties.BaselineSettings.LearningSettings();
        learning.setEnabled(true);
        baseline.setLearning(learning);
        properties.setBaseline(baseline);
        InMemoryBaselineDataStore store = new InMemoryBaselineDataStore();
        BaselineLearningService service = new BaselineLearningService(store, properties);

        int threads = 8;
        int perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        Instant base = Instant.parse("2026-10-23T09:00:00Z");
        for (int t = 0; t < threads; t++) {
            int thread = t;
            results.add(pool.submit(() -> {
                start.await();
                int learned = 0;
                for (int i = 0; i < perThread; i++) {
                    SecurityEvent event = SecurityEvent.builder()
                            .sourceIp("10.20.30.5")
                            .userAgent(CHROME)
                            .timestamp(base.plusSeconds(thread * 1000L + i))
                            .build();
                    SecurityDecision decision = SecurityDecision.builder()
                            .action(ZeroTrustAction.ALLOW)
                            .riskScore(0.1)
                            .confidence(1.0)
                            .build();
                    if (service.learnIfNormal("lq-burst", decision, event)) {
                        learned++;
                    }
                }
                return learned;
            }));
        }
        start.countDown();
        int reportedLearned = 0;
        for (Future<Integer> result : results) {
            reportedLearned += result.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();

        BaselineVector stored = store.getUserBaseline("lq-burst");
        assertThat(reportedLearned).isEqualTo(threads * perThread);
        assertThat(stored.getUpdateCount()).isEqualTo((long) threads * perThread);
        assertThat(service.lostLearnings()).isZero();
    }
}
