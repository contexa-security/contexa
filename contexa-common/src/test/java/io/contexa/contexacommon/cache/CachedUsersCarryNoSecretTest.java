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
package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.Users;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-87: a user's copy in the caches, in memory and on the real Redis ({@code CONTEXA_BACKLOG_REDIS_PORT}, unique
 * keys). What leaves the process is JSON, so the password hash never reaches it, and a copy written before this was so
 * is still read.
 */
class CachedUsersCarryNoSecretTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String HASH = "{bcrypt}$2a$10$hashOfTheUsersPasswordHashOfTheUsersPassword";
    private static final String DOMAIN = "users";
    private static final TypeReference<Users> USERS_TYPE = new TypeReference<>() {
    };

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate strings;

    @BeforeAll
    static void connect() {
        String port = System.getenv(REDIS_PORT);
        if (port == null || !port.matches("[0-9]+")) {
            return;
        }
        factory = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(port));
        factory.afterPropertiesSet();
        strings = new StringRedisTemplate(factory);
    }

    @AfterAll
    static void close() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @Test
    @DisplayName("PR-87: no mapper the stores use writes the password hash of a user")
    void noMapperWritesThePasswordHash() throws JsonProcessingException {
        ObjectMapper everyField = new ObjectMapper();
        everyField.findAndRegisterModules();
        everyField.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);

        for (ObjectMapper mapper : List.of(ContexaCacheAutoConfiguration.ownObjectMapper(), everyField)) {
            assertThat(mapper.writeValueAsString(user())).doesNotContain("password\"").doesNotContain(HASH)
                    .contains("\"username\":\"kim\"");
        }
    }

    @Test
    @DisplayName("PR-87: a copy written before keeps being read, and its password hash does not come back with it")
    void aCopyWrittenBeforeIsReadWithoutItsHash() throws JsonProcessingException {
        String written = "{\"id\":7,\"username\":\"kim\",\"password\":\"" + HASH + "\",\"mfaEnabled\":true}";
        ObjectMapper strict = ContexaCacheAutoConfiguration.ownObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        Users copy = strict.readValue(written, USERS_TYPE);

        assertThat(copy.getId()).isEqualTo(7L);
        assertThat(copy.isMfaEnabled()).isTrue();
        assertThat(copy.getPassword()).isNull();
    }

    @Test
    @DisplayName("PR-87: the memory cache keeps no hash, and the copy it answers with holds none")
    void theMemoryCacheKeepsNoHash() {
        ContexaCacheProperties properties = new ContexaCacheProperties();
        LocalContexaCacheService cache = new LocalContexaCacheService(properties,
                ContexaCacheAutoConfiguration.ownObjectMapper());
        cache.init();
        String key = "user_details:" + UUID.randomUUID();
        AtomicInteger loads = new AtomicInteger();

        Users loaded = cache.get(key, () -> {
            loads.incrementAndGet();
            return user();
        }, USERS_TYPE, DOMAIN);
        Users copy = cache.get(key, () -> {
            loads.incrementAndGet();
            return user();
        }, USERS_TYPE, DOMAIN);

        assertThat(cache.getOrCreateDomainCache(DOMAIN).getIfPresent(key)).doesNotContain(HASH)
                .doesNotContain("password\"");
        assertThat(loads.get()).as("the second read is the cached copy").isEqualTo(1);
        assertThat(loaded.getPassword()).as("the entity the loader returned stays as it is").isEqualTo(HASH);
        assertThat(copy.getPassword()).isNull();
        assertThat(copy.getUsername()).isEqualTo("kim");
    }

    @ParameterizedTest
    @EnumSource(value = ContexaCacheProperties.CacheType.class, names = {"REDIS", "HYBRID"})
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    @DisplayName("PR-87: Redis keeps no hash under the production key, in both distributed cache types")
    void redisKeepsNoHash(ContexaCacheProperties.CacheType type) {
        ContexaCacheProperties properties = new ContexaCacheProperties();
        properties.setType(type);
        RedisContexaCacheService cache = new RedisContexaCacheService(properties, strings,
                ContexaCacheAutoConfiguration.ownObjectMapper());
        cache.init();
        String key = "user_details:" + UUID.randomUUID();
        String stored = properties.getRedis().getKeyPrefix() + key;

        try {
            cache.get(key, CachedUsersCarryNoSecretTest::user, USERS_TYPE, DOMAIN);
            Users copy = cache.get(key, () -> null, USERS_TYPE, DOMAIN);

            assertThat(strings.opsForValue().get(stored)).contains("\"username\":\"kim\"").doesNotContain(HASH)
                    .doesNotContain("password\"");
            assertThat(copy.getUsername()).isEqualTo("kim");
            assertThat(copy.getPassword()).isNull();
        } finally {
            strings.delete(stored);
        }
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    @DisplayName("PR-87: a copy with a hash already in Redis is still read, without the hash")
    void aCopyAlreadyInRedisIsReadWithoutItsHash() {
        ContexaCacheProperties properties = new ContexaCacheProperties();
        RedisContexaCacheService cache = new RedisContexaCacheService(properties, strings,
                ContexaCacheAutoConfiguration.ownObjectMapper());
        cache.init();
        String key = "user_details:" + UUID.randomUUID();
        String stored = properties.getRedis().getKeyPrefix() + key;
        strings.opsForValue().set(stored, "{\"id\":7,\"username\":\"kim\",\"password\":\"" + HASH + "\"}");

        try {
            Users copy = cache.get(key, () -> null, USERS_TYPE, DOMAIN);

            assertThat(copy.getUsername()).isEqualTo("kim");
            assertThat(copy.getPassword()).isNull();
        } finally {
            strings.delete(stored);
        }
    }

    private static Users user() {
        return Users.builder().id(7L).username("kim").name("Kim").email("kim@example.test").password(HASH)
                .mfaEnabled(true).build();
    }
}
