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

import io.contexa.contexacommon.store.StoreFailures;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.Nullable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.time.Duration;
import java.util.Base64;

/**
 * The step-up options shared by every instance of a distributed deployment, so the answer may reach another instance
 * than the one that handed the options out. Same expiry and read-once rule as the in-memory store. Only the classes a
 * step-up keeps are read back from the stored bytes.
 */
@Slf4j
public class RedisStepUpOptionsStore implements StepUpOptionsStore {

    private static final String PREFIX = "contexa:step-up:options:";
    private static final String CLAIM = "claim:";

    private static final ObjectInputFilter ALLOWED = ObjectInputFilter.Config.createFilter(
            "java.lang.*;java.util.*;java.time.*;"
                    + "org.springframework.security.web.webauthn.api.*;"
                    + "io.contexa.contexaidentity.security.webauthn.state.*;"
                    + "!*");

    private final StringRedisTemplate redis;

    public RedisStepUpOptionsStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** D-19: an option Redis does not take is an option the answer will not find, and the step-up starts again. */
    @Override
    public void put(String key, Serializable value) {
        String encoded = encode(value);
        try {
            redis.opsForValue().set(PREFIX + key, encoded, TIME_TO_LIVE);
        } catch (RuntimeException unavailable) {
            report("keep a step-up option", unavailable);
        }
    }

    /** A claim Redis cannot give is not given: what it guards does not happen, and the user stays stopped. */
    @Override
    public boolean claim(String key, Duration holdFor) {
        try {
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(PREFIX + CLAIM + key, "1", holdFor));
        } catch (RuntimeException unavailable) {
            report("claim a step-up option", unavailable);
            return false;
        }
    }

    @Override
    public void release(String key) {
        try {
            redis.delete(PREFIX + CLAIM + key);
        } catch (RuntimeException unavailable) {
            report("release a step-up claim", unavailable);
        }
    }

    @Override
    public boolean holds(String key) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + key));
    }

    @Override
    @Nullable
    public <T extends Serializable> T take(String key, Class<T> type) {
        String stored;
        try {
            stored = redis.opsForValue().getAndDelete(PREFIX + key);
        } catch (RuntimeException unavailable) {
            report("read a step-up option", unavailable);
            return null;
        }
        if (stored == null) {
            return null;
        }
        Object value = decode(stored);
        return type.isInstance(value) ? type.cast(value) : null;
    }

    private static void report(String what, RuntimeException failure) {
        if (!StoreFailures.isReportedOutage(failure)) {
            log.error("[StepUp] Redis did not {}", what, failure);
        }
    }

    private static String encode(Serializable value) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        } catch (IOException e) {
            throw new IllegalStateException("A step-up option could not be stored", e);
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    @Nullable
    private static Object decode(String stored) {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(stored)))) {
            in.setObjectInputFilter(ALLOWED);
            return in.readObject();
        } catch (IOException | ClassNotFoundException | IllegalArgumentException e) {
            log.error("[StepUp] A stored step-up option could not be read; the step-up starts again", e);
            return null;
        }
    }
}
