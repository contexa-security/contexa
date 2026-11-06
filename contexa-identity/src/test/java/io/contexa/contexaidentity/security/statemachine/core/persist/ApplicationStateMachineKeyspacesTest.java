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
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisKeyValueTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.index.IndexConfiguration;
import org.springframework.data.redis.core.convert.MappingConfiguration;
import org.springframework.data.redis.core.mapping.RedisMappingContext;
import org.springframework.data.redis.repository.support.RedisRepositoryFactory;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.data.redis.RedisRepositoryAction;
import org.springframework.statemachine.data.redis.RedisRepositoryGuard;
import org.springframework.statemachine.data.redis.RedisRepositoryState;
import org.springframework.statemachine.data.redis.RedisRepositoryStateMachine;
import org.springframework.statemachine.data.redis.RedisRepositoryTransition;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The MFA flows Spring Statemachine keeps in Redis are a named application's own: the keyspace of every repository entity
 * is behind the name, and another application sharing the Redis finds none of the flows. Keys of their own in a shared
 * Redis: nothing here flushes it.
 */
class ApplicationStateMachineKeyspacesTest {

    private static final List<Class<?>> ENTITIES = List.of(RedisRepositoryStateMachine.class,
            RedisRepositoryState.class, RedisRepositoryTransition.class, RedisRepositoryAction.class,
            RedisRepositoryGuard.class);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate strings;

    private final List<String> keysToRemove = new ArrayList<>();

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        strings = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void clean() {
        keysToRemove.forEach(strings::delete);
    }

    private static RedisMappingContext mappingContext() {
        return new RedisMappingContext(new MappingConfiguration(new IndexConfiguration(), new ApplicationStateMachineKeyspaces()));
    }

    /** The repository the way the distributed mode makes it: over a mapping context with these keyspaces. */
    private static RedisStateMachineRepository repository() {
        RedisTemplate<byte[], byte[]> bytes = new RedisTemplate<>();
        bytes.setConnectionFactory(connectionFactory);
        bytes.afterPropertiesSet();
        RedisMappingContext mappingContext = mappingContext();
        RedisKeyValueAdapter adapter = new RedisKeyValueAdapter(bytes, mappingContext);
        return new RedisRepositoryFactory(new RedisKeyValueTemplate(adapter, mappingContext))
                .getRepository(RedisStateMachineRepository.class);
    }

    @Test
    @DisplayName("an application with a name keeps the entities of the repositories under ctxa:<name>: and one without keeps its keyspaces")
    void everyKeyspaceIsBehindTheName() {
        for (Class<?> entity : ENTITIES) {
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
                assertThat(mappingContext().getRequiredPersistentEntity(entity).getKeySpace())
                        .isEqualTo("ctxa:shop:" + entity.getSimpleName());
            }
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
                assertThat(mappingContext().getRequiredPersistentEntity(entity).getKeySpace())
                        .isEqualTo(entity.getSimpleName());
            }
        }
    }

    @Test
    @DisplayName("the entity of the persist, which the library does not know, is stored in the keyspace of the library's entity")
    void theExpiringEntityHasTheKeyspaceOfItsParent() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(mappingContext().getRequiredPersistentEntity(
                    ExpiringRedisRepositoryStateMachinePersist.ExpiringRedisRepositoryStateMachine.class).getKeySpace())
                    .isEqualTo("ctxa:shop:RedisRepositoryStateMachine");
        }
    }

    @Test
    @DisplayName("a flow of a named application is stored under ctxa:<name>:RedisRepositoryStateMachine:<id> with its time to live, and another application does not find it")
    void aFlowIsTheApplicationsOwn() throws Exception {
        String id = "keyspace-" + UUID.randomUUID();
        String key = "ctxa:shop:RedisRepositoryStateMachine:" + id;
        keysToRemove.add(key);
        keysToRemove.add("RedisRepositoryStateMachine:" + id);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            persist(Duration.ofMinutes(30)).write(context(), id);

            assertThat(strings.getExpire(key, TimeUnit.SECONDS))
                    .isBetween(Duration.ofMinutes(29).toSeconds(), Duration.ofMinutes(30).toSeconds());
            assertThat(strings.hasKey("RedisRepositoryStateMachine:" + id)).as("not under the key it had without a name").isFalse();
            assertThat(persist(Duration.ofMinutes(30)).read(id)).as("the other server of the application").isNotNull();
            assertThat(key).isEqualTo(ApplicationNamespace.key("RedisRepositoryStateMachine:" + id));
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("clinic")) {
            assertThat(persist(Duration.ofMinutes(30)).read(id)).as("another application").isNull();
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(persist(Duration.ofMinutes(30)).read(id)).as("an application without a name").isNull();
        }
    }

    @Test
    @DisplayName("an application without a name keeps the key it always had")
    void anUnnamedApplicationKeepsItsKey() throws Exception {
        String id = "keyspace-" + UUID.randomUUID();
        keysToRemove.add("RedisRepositoryStateMachine:" + id);

        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            persist(Duration.ofMinutes(30)).write(context(), id);

            assertThat(strings.hasKey("RedisRepositoryStateMachine:" + id)).isTrue();
        }
    }

    private static ExpiringRedisRepositoryStateMachinePersist persist(Duration ttl) {
        return new ExpiringRedisRepositoryStateMachinePersist(repository(), new MfaKryoStateMachineSerialisationService(), ttl);
    }

    private static StateMachineContext<MfaState, MfaEvent> context() {
        return new DefaultStateMachineContext<>(MfaState.AWAITING_FACTOR_SELECTION, null, null,
                new DefaultExtendedState(), null, "mfa");
    }
}
