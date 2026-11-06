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
package io.contexa.contexacore.namespace;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The signals a server sends to the others of its application, a BLOCK or a reload of the policy, travel on a channel of
 * the application's own: another application sharing the Redis neither hears them nor sends any to this one.
 */
class RedissonTopicsApplicationTest {

    private final RedissonClient redisson = mock(RedissonClient.class);
    private final RTopic topic = mock(RTopic.class);

    @Test
    @DisplayName("the block signal and the policy reload signal are channels behind the name of the application")
    void signalsTravelBehindTheName() {
        when(redisson.getTopic(anyString())).thenReturn(topic);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            new BlockingDecisionRegistry(redisson);
            new PolicyReloadBroadcaster(redisson, () -> {
            });
        }

        verify(redisson).getTopic("ctxa:shop:contexa:security:block-signal");
        verify(redisson).getTopic("ctxa:shop:contexa:policy:reload-signal");
    }

    @Test
    @DisplayName("an application without a name keeps the channels it always had")
    void anUnnamedApplicationKeepsItsChannels() {
        when(redisson.getTopic(anyString())).thenReturn(topic);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            new BlockingDecisionRegistry(redisson);
            new PolicyReloadBroadcaster(redisson, () -> {
            });
        }

        verify(redisson).getTopic("contexa:security:block-signal");
        verify(redisson).getTopic("contexa:policy:reload-signal");
    }

    @Test
    @DisplayName("the approval channel of the SOAR notifier is behind the name too")
    void theApprovalChannelIsBehindTheName() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(UnifiedRedisConfiguration.soarApprovalChannel()).isEqualTo("ctxa:shop:soar:approval:requests");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(UnifiedRedisConfiguration.soarApprovalChannel()).isEqualTo("soar:approval:requests");
        }
    }
}
