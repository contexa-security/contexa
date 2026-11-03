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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectOutputStream;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisStepUpOptionsStoreTest {

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private RedisStepUpOptionsStore store;

    @BeforeEach
    void setUp() {
        when(redis.opsForValue()).thenReturn(values);
        store = new RedisStepUpOptionsStore(redis);
    }

    @Test
    @DisplayName("a claim is one atomic set-if-absent with the time to hold, so nodes do not both win")
    void aClaimIsAtomic() {
        Duration hold = Duration.ofSeconds(30);
        when(values.setIfAbsent("contexa:step-up:options:claim:code-sent:7", "1", hold)).thenReturn(true, false);

        assertThat(store.claim("code-sent:7", hold)).isTrue();
        assertThat(store.claim("code-sent:7", hold)).isFalse();
    }

    @Test
    @DisplayName("a claim that Redis cannot answer (null) is not given")
    void anUnansweredClaimIsNotGiven() {
        when(values.setIfAbsent("contexa:step-up:options:claim:k", "1", Duration.ofMinutes(1))).thenReturn(null);

        assertThat(store.claim("k", Duration.ofMinutes(1))).isFalse();
    }

    @Test
    @DisplayName("a released claim is deleted")
    void aReleasedClaimIsDeleted() {
        store.release("code-sent:7");

        verify(redis).delete("contexa:step-up:options:claim:code-sent:7");
    }

    /**
     * Exception test: whatever is in Redis is not trusted. A value written by someone else (a shared Redis, a leaked
     * credential) must not be deserialised into a class outside the few the step-up stores.
     */
    @Test
    @DisplayName("a stored value of a class outside the allowed ones is refused, not deserialised")
    void aForeignClassIsRefused() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(new File("/tmp/not-allowed"));
        }
        when(values.getAndDelete("contexa:step-up:options:assertion:alice"))
                .thenReturn(Base64.getEncoder().encodeToString(bytes.toByteArray()));

        assertThat(store.take("assertion:alice", File.class)).isNull();
    }

    @Test
    @DisplayName("garbage, a cut value and a value of another type give nothing, and no error reaches the caller")
    void garbageGivesNothing() throws Exception {
        for (String stored : new String[] {"not base64 !!", "", "AAAA", Base64.getEncoder().encodeToString(new byte[] {1, 2, 3})}) {
            when(values.getAndDelete("contexa:step-up:options:k")).thenReturn(stored);

            assertThat(store.take("k", HashMap.class)).isNull();
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(new HashMap<>(Map.of("a", "b")));
        }
        when(values.getAndDelete("contexa:step-up:options:k")).thenReturn(Base64.getEncoder().encodeToString(bytes.toByteArray()));
        assertThat(store.take("k", String.class)).as("another type").isNull();
    }
}
