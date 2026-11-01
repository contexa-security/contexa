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

import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachine;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachinePersist;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.service.StateMachineSerialisationService;

import java.time.Duration;
import java.util.Objects;

/**
 * Redis MFA state machine contexts that lapse. Z-16 (F6): {@code RedisRepositoryStateMachine} has no TTL, so an
 * abandoned flow stayed in Redis for good; each write here gives the context's key (the same
 * {@code RedisRepositoryStateMachine:} key) the persistence TTL
 * ({@code contexa.identity.statemachine.persistence.ttl-minutes}), as InMemoryStateMachinePersist lets its context lapse
 * that long after its last write.
 */
public class ExpiringRedisRepositoryStateMachinePersist extends RedisRepositoryStateMachinePersist<MfaState, MfaEvent> {

    private final long ttlSeconds;

    public ExpiringRedisRepositoryStateMachinePersist(RedisStateMachineRepository repository,
            StateMachineSerialisationService<MfaState, MfaEvent> serialisationService, Duration ttl) {
        super(repository, serialisationService);
        this.ttlSeconds = Math.max(1, Objects.requireNonNull(ttl, "ttl").toSeconds());
    }

    @Override
    protected RedisRepositoryStateMachine build(StateMachineContext<MfaState, MfaEvent> context, Object contextObj,
                                                byte[] serialisedContext) {
        ExpiringRedisRepositoryStateMachine machine = new ExpiringRedisRepositoryStateMachine();
        machine.setId(contextObj.toString());
        machine.setMachineId(context.getId());
        machine.setState(context.getState().toString());
        machine.setStateMachineContext(serialisedContext);
        machine.setTimeToLive(ttlSeconds);
        return machine;
    }

    /** The library's entity, in its keyspace, with the time to live of the write. */
    public static class ExpiringRedisRepositoryStateMachine extends RedisRepositoryStateMachine {

        @TimeToLive
        private Long timeToLive;

        public Long getTimeToLive() {
            return timeToLive;
        }

        public void setTimeToLive(Long timeToLive) {
            this.timeToLive = timeToLive;
        }
    }
}
