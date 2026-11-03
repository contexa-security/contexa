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

import org.springframework.lang.Nullable;

import java.io.Serializable;
import java.time.Duration;

/**
 * Keeps what a step-up hands out until the user answers it (the passkey challenge, the options of a passkey
 * registration), under the user's decision key instead of the application's HTTP session: when the application owns
 * sign-in Contexa does not write into its session (ownership design S-2). An entry is read once.
 */
public interface StepUpOptionsStore {

    /** How long an entry waits for its answer. */
    Duration TIME_TO_LIVE = Duration.ofMinutes(5);

    void put(String key, Serializable value);

    /**
     * Claims the key for the time given: true for the first caller, false while someone holds it. One claim at a
     * time, across nodes when the store is shared. For what may happen once in a while (the mail of a code) or once
     * (the spending of a code), where a check and a later write would let two requests at once both pass.
     */
    boolean claim(String key, Duration holdFor);

    /** Gives a claim up before its time is over. */
    void release(String key);

    /** The entry under the key, removed; null when there is none, it expired, or it is of another type. */
    @Nullable
    <T extends Serializable> T take(String key, Class<T> type);
}
