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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The standalone mode keeps a BLOCK in the memory of the server, which a restart empties; the database record of the
 * blocks in force is the second copy, and the start writes it again. A server that has just started is a new memory.
 */
class RestrictionRestorerStandaloneTest {

    private ApplicationNamespace.Scope unnamed;

    @BeforeEach
    void withoutAName() {
        unnamed = ApplicationNamespace.using("");
    }

    @AfterEach
    void restoreTheName() {
        unnamed.close();
    }

    /** The record of the database: the blocks it holds in force. */
    private static IBlockedUserRecorder database(String... inForce) {
        return new IBlockedUserRecorder() {
            @Override
            public void recordBlock(String requestId, String userId, String username, String action, String reasoning,
                                    String sourceIp, String userAgent) {
            }

            @Override
            public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
            }

            @Override
            public List<String> blocksInForce() {
                return List.of(inForce);
            }
        };
    }

    private static void start(ZeroTrustActionRepository actions, IBlockedUserRecorder recorder) {
        NamespaceRestrictionRestorer restorer = new NamespaceRestrictionRestorer(() -> actions, () -> recorder,
                InMemorySecurityContextDataStore::new, Duration.ofSeconds(10), List.of(Duration.ofMillis(50)));
        restorer.start();
        restorer.stop();
    }

    @Test
    @DisplayName("a block in force before a restart is in force after it: the new memory is written from the record")
    void aBlockInForceBeforeARestartIsInForceAfterIt() {
        InMemoryZeroTrustActionRepository beforeTheRestart = new InMemoryZeroTrustActionRepository(0);
        beforeTheRestart.setBlockedFlag("alice");
        assertThat(beforeTheRestart.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);

        InMemoryZeroTrustActionRepository afterTheRestart = new InMemoryZeroTrustActionRepository(0);
        assertThat(afterTheRestart.getCurrentAction("alice")).as("the memory is empty").isNotEqualTo(ZeroTrustAction.BLOCK);

        start(afterTheRestart, database("alice"));

        assertThat(afterTheRestart.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a block an administrator released is not written again: the record does not hold it in force")
    void aReleasedBlockIsNotWrittenAgain() {
        InMemoryZeroTrustActionRepository afterTheRestart = new InMemoryZeroTrustActionRepository(0);

        start(afterTheRestart, database("alice"));

        assertThat(afterTheRestart.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(afterTheRestart.getCurrentAction("bob")).as("released: not in the record's list")
                .isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a block the memory already has, and what a verification did to it, are left as they are")
    void anExistingBlockIsLeftAsItIs() {
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository(0);
        memory.setBlockedFlag("alice");
        memory.setBlockMfaVerified("alice", Duration.ofMinutes(10));

        start(memory, database("alice"));

        assertThat(memory.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(memory.getBlockMfaVerifiedUntil("alice")).as("not reset by the start").isNotNull();
    }

    @Test
    @DisplayName("without a record of blocks (no contexa-iam) nothing is written, and the start goes on")
    void withoutARecordNothingIsWritten() {
        InMemoryZeroTrustActionRepository afterTheRestart = new InMemoryZeroTrustActionRepository(0);

        assertThatCode(() -> start(afterTheRestart, null)).doesNotThrowAnyException();
        assertThatCode(() -> start(afterTheRestart, new IBlockedUserRecorder() {
            @Override
            public void recordBlock(String requestId, String userId, String username, String action, String reasoning,
                                    String sourceIp, String userAgent) {
            }

            @Override
            public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
            }
        })).doesNotThrowAnyException();

        assertThat(afterTheRestart.getCurrentAction("alice")).isNotEqualTo(ZeroTrustAction.BLOCK);
    }
}
