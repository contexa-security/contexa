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
package io.contexa.contexacommon.config.redis;

import io.contexa.contexacommon.store.StoreGate;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.lang.Nullable;

import java.util.List;

/** {@link WatchedRedisTemplate} for strings: Contexa's code asks for a {@link StringRedisTemplate} by type. */
final class WatchedStringRedisTemplate extends StringRedisTemplate {

    private final StoreGate gate;

    WatchedStringRedisTemplate(StoreGate gate) {
        this.gate = gate;
    }

    @Override
    @Nullable
    public <T> T execute(RedisCallback<T> action, boolean exposeConnection, boolean pipeline) {
        try {
            return super.execute(action, exposeConnection, pipeline);
        } catch (RuntimeException failure) {
            gate.fail(failure);
            throw failure;
        }
    }

    @Override
    public <T> T execute(SessionCallback<T> session) {
        try {
            return super.execute(session);
        } catch (RuntimeException failure) {
            gate.fail(failure);
            throw failure;
        }
    }

    @Override
    public List<Object> executePipelined(SessionCallback<?> session, @Nullable RedisSerializer<?> resultSerializer) {
        try {
            return super.executePipelined(session, resultSerializer);
        } catch (RuntimeException failure) {
            gate.fail(failure);
            throw failure;
        }
    }

    @Override
    public List<Object> executePipelined(RedisCallback<?> action, @Nullable RedisSerializer<?> resultSerializer) {
        try {
            return super.executePipelined(action, resultSerializer);
        } catch (RuntimeException failure) {
            gate.fail(failure);
            throw failure;
        }
    }
}
