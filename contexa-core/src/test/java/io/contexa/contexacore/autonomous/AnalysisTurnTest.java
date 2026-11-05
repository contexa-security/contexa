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

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Q-23: a line of analyses: the first decision of a session first, each kind in the order it came. */
class AnalysisTurnTest {

    @Test
    void firstDecisionsComeFirstAndEachKindKeepsItsOrder() {
        PriorityBlockingQueue<Runnable> line = new PriorityBlockingQueue<>(11, AnalysisTurn.ORDER);
        List<String> order = new ArrayList<>();
        line.add(AnalysisTurn.of(() -> order.add("decided-1"), false));
        line.add(AnalysisTurn.of(() -> order.add("first-1"), true));
        line.add(AnalysisTurn.of(() -> order.add("decided-2"), false));
        line.add(AnalysisTurn.of(() -> order.add("first-2"), true));

        while (!line.isEmpty()) {
            line.poll().run();
        }

        assertThat(order).containsExactly("first-1", "first-2", "decided-1", "decided-2");
    }

    @Test
    void workThatKnowsNoTurnWaitsBehindTheTurns() {
        PriorityBlockingQueue<Runnable> line = new PriorityBlockingQueue<>(11, AnalysisTurn.ORDER);
        List<String> order = new ArrayList<>();
        line.add(() -> order.add("plain"));
        line.add(AnalysisTurn.of(() -> order.add("decided"), false));

        while (!line.isEmpty()) {
            line.poll().run();
        }

        assertThat(order).containsExactly("decided", "plain");
    }

    @Test
    void anExecutorOnSuchALineRunsAFirstDecisionBeforeWorkThatCameEarlier() throws Exception {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new PriorityBlockingQueue<>(11, AnalysisTurn.ORDER));
        List<String> order = new ArrayList<>();
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(2);
        try {
            executor.execute(AnalysisTurn.of(() -> {
                try {
                    held.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }, false));
            executor.execute(AnalysisTurn.of(() -> {
                order.add("decided");
                done.countDown();
            }, false));
            executor.execute(AnalysisTurn.of(() -> {
                order.add("first");
                done.countDown();
            }, true));
            held.countDown();

            assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }

        assertThat(order).containsExactly("first", "decided");
    }
}
