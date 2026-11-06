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

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.springframework.data.redis.core.convert.KeyspaceConfiguration;
import org.springframework.statemachine.data.redis.RedisRepositoryAction;
import org.springframework.statemachine.data.redis.RedisRepositoryGuard;
import org.springframework.statemachine.data.redis.RedisRepositoryState;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachine;
import org.springframework.statemachine.data.redis.RedisRepositoryTransition;

import java.util.List;

/**
 * The keyspaces of the state machine repositories of Spring Statemachine, behind the name of the application when it has
 * one: the key of a stored MFA flow, the set of the flows, and their indexes are then {@code ctxa:<name>:RedisRepository...},
 * and another application sharing the Redis finds none of them. Without a name nothing is configured and the library
 * keeps the keyspaces it names itself.
 * <p>
 * Spring Data builds this configuration by its class, with the constructor that has no arguments
 * ({@code @EnableRedisRepositories(keyspaceConfiguration = ...)}).
 */
public class ApplicationStateMachineKeyspaces extends KeyspaceConfiguration {

    /** The keyspace the library gives each entity ({@code @RedisHash}). */
    private static final List<Class<?>> ENTITIES = List.of(RedisRepositoryStateMachine.class, RedisRepositoryState.class,
            RedisRepositoryTransition.class, RedisRepositoryAction.class, RedisRepositoryGuard.class);

    @Override
    protected Iterable<KeyspaceSettings> initialConfiguration() {
        if (!ApplicationNamespace.isNamed()) {
            return List.of();
        }
        return ENTITIES.stream()
                .map(entity -> new KeyspaceSettings(entity, ApplicationNamespace.key(entity.getSimpleName())))
                .toList();
    }
}
