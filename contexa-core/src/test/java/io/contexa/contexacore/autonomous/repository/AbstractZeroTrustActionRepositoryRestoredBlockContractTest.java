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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A BLOCK has no expiry, so one the record of blocks holds in force is written again when a store has lost it (the keys
 * an application had before it was given a name). The memory and the Redis store answer alike.
 */
abstract class AbstractZeroTrustActionRepositoryRestoredBlockContractTest {

    private static final String CONTEXT = "context-1";

    protected ZeroTrustActionRepository repository;
    protected String user;

    protected abstract ZeroTrustActionRepository createRepository();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
        user = "restored-" + UUID.randomUUID().toString().replace("-", "");
    }

    @Test
    @DisplayName("a BLOCK the store does not hold is written, and stops the user")
    void aMissingBlockIsWritten() {
        assertThat(repository.getCurrentAction(user, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);

        assertThat(repository.restoreBlockedFlag(user)).isTrue();

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a BLOCK the store holds is left as it is")
    void aBlockThatIsThereIsLeftAlone() {
        repository.setBlockedFlag(user);

        assertThat(repository.restoreBlockedFlag(user)).isFalse();

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("writing it twice is writing it once")
    void restoringTwiceWritesOnce() {
        assertThat(repository.restoreBlockedFlag(user)).isTrue();
        assertThat(repository.restoreBlockedFlag(user)).isFalse();
    }

    @Test
    @DisplayName("an administrator's release lifts a restored BLOCK as it lifts any other")
    void aRestoredBlockIsReleased() {
        repository.restoreBlockedFlag(user);

        repository.removeBlockedFlag(user);

        assertThat(repository.getCurrentAction(user, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.restoreBlockedFlag(user)).as("the record would say so again only while it holds the block").isTrue();
    }

    @Test
    @DisplayName("every spelling of the name reads the restored BLOCK, as it reads one set the usual way")
    void everySpellingReadsTheRestoredBlock() {
        repository.restoreBlockedFlag(user.toUpperCase());

        assertThat(repository.getCurrentAction(user, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(" " + user + " ", CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a console session's and an agent's keys are restored as keys, not read as the person's")
    void keysAreRestoredAsKeys() {
        String console = "console::" + user;

        repository.restoreBlockedFlag(console);

        assertThat(repository.getCurrentAction(console, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(user, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a blank id writes nothing")
    void aBlankIdWritesNothing() {
        assertThat(repository.restoreBlockedFlag(null)).isFalse();
        assertThat(repository.restoreBlockedFlag("")).isFalse();
        assertThat(repository.restoreBlockedFlag("  ")).isFalse();
    }
}
