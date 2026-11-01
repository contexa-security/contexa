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
package io.contexa.contexaidentity.security.statemachine.core.persist;

import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import lombok.extern.slf4j.Slf4j;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * In-memory MFA state machine contexts. Z-16 (F6): as ExpiringRedisRepositoryStateMachinePersist, a context lapses the
 * persistence TTL ({@code contexa.identity.statemachine.persistence.ttl-minutes}) after its last write, so an abandoned
 * flow does not stay; a read does not keep it, and the sweep releases it. The contexts are an {@link ExpiringKeySpace}
 * (N-1).
 */
@Slf4j
@Component
public class InMemoryStateMachinePersist
        implements StateMachinePersist<MfaState, MfaEvent, String>, ExpiringStateStore {

    private static final String KEY_PREFIX = "mfa:statemachine:";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(30);

    private final ExpiringKeySpace<StateMachineContext<MfaState, MfaEvent>> storage;

    public InMemoryStateMachinePersist() {
        this(DEFAULT_TTL);
    }

    public InMemoryStateMachinePersist(Duration ttl) {
        this.storage = ExpiringKeySpace.<StateMachineContext<MfaState, MfaEvent>>builder(Clock.systemUTC())
                .ttl(Objects.requireNonNull(ttl, "ttl"))
                .build();
    }

    @Override
    public void write(StateMachineContext<MfaState, MfaEvent> context, String contextObj) throws Exception {
        if (context == null) {
            // Nothing to keep: the context reads as absent, as it did.
            storage.remove(KEY_PREFIX + contextObj);
            return;
        }
        storage.put(KEY_PREFIX + contextObj, context);
    }

    @Override
    public StateMachineContext<MfaState, MfaEvent> read(String contextObj) throws Exception {
        return storage.get(KEY_PREFIX + contextObj);
    }

    public void delete(String contextObj) {
        storage.remove(KEY_PREFIX + contextObj);
    }

    @Override
    public void removeExpiredEntries() {
        storage.removeExpired();
    }

    boolean holdsContextFor(String contextObj) {
        return storage.holds(KEY_PREFIX + contextObj);
    }
}
