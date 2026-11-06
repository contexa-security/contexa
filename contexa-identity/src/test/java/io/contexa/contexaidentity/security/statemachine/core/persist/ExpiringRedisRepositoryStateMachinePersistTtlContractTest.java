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

import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisKeyValueTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.mapping.RedisMappingContext;
import org.springframework.data.redis.repository.support.RedisRepositoryFactory;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** The Redis persist on a Spring Data repository, as the distributed mode's {@code @EnableRedisRepositories} makes. */
class ExpiringRedisRepositoryStateMachinePersistTtlContractTest extends AbstractMfaStateMachinePersistTtlContractTest {

    private static LettuceConnectionFactory connectionFactory;
    private static RedisStateMachineRepository repository;
    private static StringRedisTemplate strings;

    private ExpiringRedisRepositoryStateMachinePersist persist;

    @BeforeAll
    static void connect() {
        TestStores.Redis server = TestStores.redis();
        connectionFactory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(server.host(), server.port()));
        connectionFactory.afterPropertiesSet();
        RedisTemplate<byte[], byte[]> bytes = new RedisTemplate<>();
        bytes.setConnectionFactory(connectionFactory);
        bytes.afterPropertiesSet();
        RedisMappingContext mappingContext = new RedisMappingContext();
        RedisKeyValueAdapter adapter = new RedisKeyValueAdapter(bytes, mappingContext);
        repository = new RedisRepositoryFactory(new RedisKeyValueTemplate(adapter, mappingContext))
                .getRepository(RedisStateMachineRepository.class);
        strings = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @AfterEach
    void removeWrittenContexts() {
        writtenIds.forEach(repository::deleteById);
    }

    @Override
    protected void usePersist(Duration ttl) {
        persist = new ExpiringRedisRepositoryStateMachinePersist(repository,
                new MfaKryoStateMachineSerialisationService(), ttl);
    }

    @Override
    protected void write(StateMachineContext<MfaState, MfaEvent> context, String id) throws Exception {
        persist.write(context, id);
    }

    @Override
    protected StateMachineContext<MfaState, MfaEvent> read(String id) throws Exception {
        return persist.read(id);
    }

    @Test
    void theContextKeyCarriesTheTtl() throws Exception {
        usePersist(Duration.ofMinutes(30));
        String id = "z16-mfa-ttl-key";
        writtenIds.add(id);

        persist.write(new DefaultStateMachineContext<>(MfaState.AWAITING_FACTOR_SELECTION, null, null,
                new DefaultExtendedState(), null, "mfa"), id);

        assertThat(strings.getExpire("RedisRepositoryStateMachine:" + id, TimeUnit.SECONDS))
                .isBetween(Duration.ofMinutes(29).toSeconds(), Duration.ofMinutes(30).toSeconds());
        assertThat(strings.keys("RedisRepositoryStateMachine:" + id + "*"))
                .containsExactly("RedisRepositoryStateMachine:" + id);
    }
}
