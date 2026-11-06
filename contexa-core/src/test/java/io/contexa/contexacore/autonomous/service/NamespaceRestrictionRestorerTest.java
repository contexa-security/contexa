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

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * An application writes the blocks its database holds in force where the decision store has none, and one that is given a
 * name carries its quarantine over, before the web server takes a request. Nothing here may stop the application or hold
 * a request: an error is reported and tried again a number of times.
 */
@ExtendWith(OutputCaptureExtension.class)
class NamespaceRestrictionRestorerTest {

    private static final Duration RETRY = Duration.ofMillis(40);

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final IBlockedUserRecorder recorder = mock(IBlockedUserRecorder.class);
    private final SecurityContextDataStore store = mock(SecurityContextDataStore.class);
    private ApplicationNamespace.Scope scope;
    private NamespaceRestrictionRestorer restorer;

    @BeforeEach
    void named() {
        scope = ApplicationNamespace.using("shop");
    }

    @AfterEach
    void stopAndRestore() {
        if (restorer != null) {
            restorer.stop();
        }
        scope.close();
    }

    private NamespaceRestrictionRestorer restorer(Duration firstAttemptWait) {
        restorer = new NamespaceRestrictionRestorer(() -> actions, () -> recorder, () -> store, firstAttemptWait,
                List.of(RETRY, RETRY));
        return restorer;
    }

    @Test
    @DisplayName("it starts before the web server, whose lifecycle runs at Integer.MAX_VALUE - 2048")
    void itStartsBeforeTheWebServer() {
        assertThat(NamespaceRestrictionRestorer.PHASE).isLessThan(Integer.MAX_VALUE - 2048);
        assertThat(restorer(Duration.ofSeconds(5)).getPhase()).isEqualTo(NamespaceRestrictionRestorer.PHASE);
        assertThat(restorer.isAutoStartup()).isTrue();
    }

    @Test
    @DisplayName("a named application writes each block the database holds in force, under the id it was recorded with, before start returns")
    void theBlocksInForceAreWrittenBeforeStartReturns() {
        when(recorder.blocksInForce()).thenReturn(List.of("alice", "console::bob"));
        when(actions.restoreBlockedFlag("alice")).thenReturn(true);
        when(actions.restoreBlockedFlag("console::bob")).thenReturn(false);

        restorer(Duration.ofSeconds(5)).start();

        verify(actions).restoreBlockedFlag("alice");
        verify(actions).restoreBlockedFlag("console::bob");
        verify(store).carryOverLearningQuarantine();
        assertThat(restorer.isRunning()).isTrue();
    }

    @Test
    @DisplayName("an application without a name writes the blocks in force too, and carries no quarantine: it has no earlier key")
    void anUnnamedApplicationWritesTheBlocksAndCarriesNoQuarantine() {
        when(recorder.blocksInForce()).thenReturn(List.of("alice"));
        scope.close();
        try (ApplicationNamespace.Scope unnamed = ApplicationNamespace.using("")) {
            restorer(Duration.ofSeconds(5)).start();
        }
        scope = ApplicationNamespace.using("shop");

        verify(actions).restoreBlockedFlag("alice");
        verify(store, never()).carryOverLearningQuarantine();
    }

    @Test
    @DisplayName("an application without a name and without a record of blocks writes nothing and stops nothing")
    void anUnnamedApplicationWithoutARecordWritesNothing() {
        scope.close();
        try (ApplicationNamespace.Scope unnamed = ApplicationNamespace.using("")) {
            restorer = new NamespaceRestrictionRestorer(() -> actions, () -> null, () -> store, Duration.ofSeconds(5),
                    List.of(RETRY));
            assertThatCode(restorer::start).doesNotThrowAnyException();
        }
        scope = ApplicationNamespace.using("shop");

        verifyNoInteractions(actions, store);
        assertThat(restorer.isRunning()).isTrue();
    }

    @Test
    @DisplayName("a database that cannot be read does not stop the application: the error is reported and the block is written on a later try")
    void aDatabaseErrorIsReportedAndTriedAgain(CapturedOutput output) {
        when(recorder.blocksInForce()).thenThrow(new IllegalStateException("database is down")).thenReturn(List.of("alice"));

        assertThatCode(() -> restorer(Duration.ofSeconds(5)).start()).doesNotThrowAnyException();

        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> verify(actions).restoreBlockedFlag("alice"));
        assertThat(output).contains("ERROR").contains("could not be restored").contains("database is down");
        verify(recorder, times(2)).blocksInForce();
    }

    @Test
    @DisplayName("a Redis that cannot be written does not stop the application either, and the quarantine is carried each time")
    void aRedisErrorIsReportedAndTriedAgain(CapturedOutput output) {
        when(recorder.blocksInForce()).thenReturn(List.of("alice"));
        when(actions.restoreBlockedFlag("alice")).thenThrow(new IllegalStateException("redis is down")).thenReturn(true);

        assertThatCode(() -> restorer(Duration.ofSeconds(5)).start()).doesNotThrowAnyException();

        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> verify(actions, times(2)).restoreBlockedFlag("alice"));
        assertThat(output).contains("redis is down");
        verify(store, times(2)).carryOverLearningQuarantine();
    }

    @Test
    @DisplayName("after the last try it says so once more at ERROR, and stops trying")
    void itGivesUpAfterTheLastTry(CapturedOutput output) throws InterruptedException {
        when(recorder.blocksInForce()).thenThrow(new IllegalStateException("database is down"));

        assertThatCode(() -> restorer(Duration.ofSeconds(5)).start()).doesNotThrowAnyException();

        Awaitility.await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(output).contains("gave up"));
        Thread.sleep(300);
        verify(recorder, times(3)).blocksInForce();
        verify(actions, never()).restoreBlockedFlag(anyString());
    }

    @Test
    @DisplayName("a database that does not answer holds start for the first wait only, and the write goes on in the background")
    void aSlowDatabaseDoesNotHoldTheStart() throws InterruptedException {
        CountDownLatch release = new CountDownLatch(1);
        when(recorder.blocksInForce()).thenAnswer(call -> {
            release.await(10, TimeUnit.SECONDS);
            return List.of("alice");
        });
        NamespaceRestrictionRestorer slow = restorer(Duration.ofMillis(300));

        long began = System.nanoTime();
        slow.start();
        long tookMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began);

        assertThat(tookMillis).as("start returned within the first wait").isLessThan(3000);
        verify(actions, never()).restoreBlockedFlag(anyString());

        release.countDown();
        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> verify(actions).restoreBlockedFlag("alice"));
    }

    @Test
    @DisplayName("without a recorder only the quarantine is carried, and without a store only the blocks are written")
    void missingPartsAreSkipped() {
        NamespaceRestrictionRestorer withoutRecorder = new NamespaceRestrictionRestorer(() -> actions, () -> null, () -> store,
                Duration.ofSeconds(5), List.of(RETRY));
        withoutRecorder.start();
        verify(store).carryOverLearningQuarantine();
        verifyNoInteractions(actions);
        withoutRecorder.stop();

        when(recorder.blocksInForce()).thenReturn(List.of("alice"));
        restorer = new NamespaceRestrictionRestorer(() -> actions, () -> recorder, () -> null, Duration.ofSeconds(5),
                List.of(RETRY));
        restorer.start();
        verify(actions).restoreBlockedFlag("alice");
    }

    @Test
    @DisplayName("stopping ends the tries that are waiting")
    void stoppingEndsTheTriesThatAreWaiting() throws InterruptedException {
        when(recorder.blocksInForce()).thenThrow(new IllegalStateException("database is down"));
        restorer(Duration.ofSeconds(5)).start();
        restorer.stop();
        int calls = mockingDetails(recorder).getInvocations().size();

        Thread.sleep(300);

        assertThat(mockingDetails(recorder).getInvocations()).hasSize(calls);
        assertThat(restorer.isRunning()).isFalse();
    }
}
