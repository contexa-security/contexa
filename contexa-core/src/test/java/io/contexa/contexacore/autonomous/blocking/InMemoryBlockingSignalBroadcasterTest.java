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
package io.contexa.contexacore.autonomous.blocking;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryBlockingSignalBroadcasterTest {

    private InMemoryBlockingSignalBroadcaster broadcaster;

    @BeforeEach
    void setUp() {
        broadcaster = new InMemoryBlockingSignalBroadcaster();
    }

    @Test
    @DisplayName("registerBlock makes user blocked")
    void registerBlock_isBlocked_returnsTrue() {
        broadcaster.registerBlock("user1");

        assertThat(broadcaster.isBlocked("user1")).isTrue();
    }

    @Test
    @DisplayName("registerUnblock makes user unblocked")
    void registerUnblock_isBlocked_returnsFalse() {
        broadcaster.registerBlock("user1");
        broadcaster.registerUnblock("user1");

        assertThat(broadcaster.isBlocked("user1")).isFalse();
    }

    @Test
    @DisplayName("isBlocked returns false for null userId")
    void isBlocked_nullUserId_returnsFalse() {
        assertThat(broadcaster.isBlocked(null)).isFalse();
    }

    @Test
    @DisplayName("isBlocked returns false for blank userId")
    void isBlocked_blankUserId_returnsFalse() {
        assertThat(broadcaster.isBlocked("")).isFalse();
        assertThat(broadcaster.isBlocked("   ")).isFalse();
    }

    @Test
    @DisplayName("isBlocked returns false for unregistered user")
    void isBlocked_unregisteredUser_returnsFalse() {
        assertThat(broadcaster.isBlocked("unknown-user")).isFalse();
    }

    @Test
    @DisplayName("registerBlock ignores null userId")
    void registerBlock_nullUserId_doesNotThrow() {
        broadcaster.registerBlock(null);

        assertThat(broadcaster.isBlocked(null)).isFalse();
    }

    @Test
    @DisplayName("registerBlock ignores blank userId")
    void registerBlock_blankUserId_doesNotAdd() {
        broadcaster.registerBlock("");

        assertThat(broadcaster.isBlocked("")).isFalse();
    }

    @Test
    @DisplayName("registerUnblock ignores null userId")
    void registerUnblock_nullUserId_doesNotThrow() {
        broadcaster.registerUnblock(null);
        // should not throw
    }

    @Test
    @DisplayName("Multiple users can be blocked independently")
    void multipleUsers_blockedIndependently() {
        broadcaster.registerBlock("user1");
        broadcaster.registerBlock("user2");

        assertThat(broadcaster.isBlocked("user1")).isTrue();
        assertThat(broadcaster.isBlocked("user2")).isTrue();

        broadcaster.registerUnblock("user1");

        assertThat(broadcaster.isBlocked("user1")).isFalse();
        assertThat(broadcaster.isBlocked("user2")).isTrue();
    }
}
