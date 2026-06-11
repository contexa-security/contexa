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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.redisson.api.RFuture;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;

import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BlockingDecisionRegistryTest {

    @Mock
    private RedissonClient redissonClient;

    @Mock
    private RTopic topic;

    @Mock
    private RFuture<Long> publishFuture;

    @Test
    @DisplayName("registerBlock 는 local block 을 먼저 반영하고 publish 실패 시 1회 재시도해야 한다")
    @SuppressWarnings("unchecked")
    void registerBlock_shouldRetryPublishOnceAfterAsyncFailure() {
        when(redissonClient.getTopic(anyString())).thenReturn(topic);
        when(topic.publishAsync(anyString())).thenReturn(publishFuture);
        when(publishFuture.whenComplete(any())).thenAnswer(invocation -> {
            BiConsumer<Long, Throwable> callback = invocation.getArgument(0);
            callback.accept(null, new IllegalStateException("redis publish failed"));
            return CompletableFuture.completedFuture(null);
        });

        BlockingDecisionRegistry registry = new BlockingDecisionRegistry(redissonClient);
        registry.registerBlock("user-1", "BLOCK");

        assertThat(registry.isBlocked("user-1")).isTrue();
        assertThat(registry.getBlockAction("user-1")).isEqualTo("BLOCK");
        verify(topic, atLeastOnce()).publishAsync(anyString());
    }

    @Test
    @DisplayName("registerUnblock 는 local unblock 을 먼저 반영하고 성공 publish 시 상태를 유지해야 한다")
    @SuppressWarnings("unchecked")
    void registerUnblock_shouldKeepLocalStateWhenPublishSucceeds() {
        when(redissonClient.getTopic(anyString())).thenReturn(topic);
        when(topic.publishAsync(anyString())).thenReturn(publishFuture);
        when(publishFuture.whenComplete(any())).thenAnswer(invocation -> {
            BiConsumer<Long, Throwable> callback = invocation.getArgument(0);
            callback.accept(1L, null);
            return CompletableFuture.completedFuture(1L);
        });

        BlockingDecisionRegistry registry = new BlockingDecisionRegistry(redissonClient);
        registry.registerBlock("user-2", "BLOCK");
        registry.registerUnblock("user-2");

        assertThat(registry.isBlocked("user-2")).isFalse();
        verify(topic, atLeastOnce()).publishAsync(anyString());
    }
}
