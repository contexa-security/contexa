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
package io.contexa.contexaiam.security.xacml.pip.context;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.cache.ContexaCacheProperties;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.cache.LocalContexaCacheService;
import io.contexa.contexacommon.cache.RedisContexaCacheService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexaiam.security.xacml.pip.attribute.DatabaseAttributePIP;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-87: the users' copies the access decisions read, through the real caches: what the readers take from a copy works
 * without the password hash, and the copies written by an earlier version can be taken out of the store.
 */
class SubjectCacheTest {

    private static final String REDIS_PORT = "CONTEXA_BACKLOG_REDIS_PORT";
    private static final String HASH = "{bcrypt}$2a$10$hashOfTheUsersPasswordHashOfTheUsersPassword";
    private static final TypeReference<Users> USERS_TYPE = new TypeReference<>() {
    };

    private final UserRepository users = mock(UserRepository.class);

    @Test
    @DisplayName("PR-87: a request read from the cached copy decides as the one read from the database, without the hash")
    void theContextHandlerWorksOnACopyWithoutTheHash() {
        LocalContexaCacheService cache = localCache();
        DefaultContextHandler handler = new DefaultContextHandler(users, cache);
        Users stored = user();
        when(users.findByIdWithGroupsRolesAndPermissions(7L)).thenReturn(Optional.of(stored));
        Authentication signedIn = signedIn();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/orders");
        when(request.getMethod()).thenReturn("GET");

        AuthorizationContext loaded = handler.create(signedIn, request);
        AuthorizationContext fromCopy = handler.create(signedIn, request);

        verify(users, times(1)).findByIdWithGroupsRolesAndPermissions(7L);
        assertThat(loaded.subjectEntity().getPassword()).isEqualTo(HASH);
        assertThat(fromCopy.subjectEntity()).isEqualTo(loaded.subjectEntity());
        assertThat(fromCopy.subjectEntity().getPassword()).isNull();
        assertThat(fromCopy.subjectEntity().getUsername()).isEqualTo("kim");
    }

    @Test
    @DisplayName("PR-87: the attributes of a user read from the cached copy are the ones read from the database")
    void theAttributePointWorksOnACopyWithoutTheHash() {
        LocalContexaCacheService cache = localCache();
        DatabaseAttributePIP pip = new DatabaseAttributePIP(users, mock(AuditLogRepository.class),
                mock(BusinessResourceActionRepository.class), cache);
        when(users.findByUsernameWithGroupsRolesAndPermissions("kim")).thenReturn(Optional.of(user()));
        AuthorizationContext context = new AuthorizationContext(new UsernamePasswordAuthenticationToken("kim", null),
                null, new ResourceDetails("URL", "/orders"), "GET",
                new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null), new HashMap<>());

        Map<String, Object> loaded = pip.getAttributes(context);
        Map<String, Object> fromCopy = pip.getAttributes(context);

        verify(users, times(1)).findByUsernameWithGroupsRolesAndPermissions("kim");
        for (String attribute : List.of("userId", "userEmail", "createdAt", "updatedAt", "mfaEnabled")) {
            assertThat(fromCopy.get(attribute)).as(attribute).isEqualTo(loaded.get(attribute)).isNotNull();
        }
    }

    @Test
    @DisplayName("PR-87: clearing takes the copies out of the memory cache and leaves what else it holds")
    void clearingTakesTheCopiesOutOfTheMemoryCache() {
        LocalContexaCacheService cache = localCache();
        AtomicInteger loads = new AtomicInteger();
        for (String key : List.of(SubjectCache.byId(7L), SubjectCache.byName("kim"))) {
            cache.put(key, user(), SubjectCache.DOMAIN);
        }
        cache.put("policies:url:all", "kept", "policies");

        SubjectCache.clear(cache);

        for (String key : List.of(SubjectCache.byId(7L), SubjectCache.byName("kim"))) {
            cache.get(key, () -> {
                loads.incrementAndGet();
                return user();
            }, USERS_TYPE, SubjectCache.DOMAIN);
        }
        assertThat(loads.get()).as("both copies were gone").isEqualTo(2);
        assertThat(cache.get("policies:url:all", () -> "reloaded", new TypeReference<String>() {
        }, "policies")).isEqualTo("kept");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = REDIS_PORT, matches = "[0-9]+")
    @DisplayName("PR-87: clearing takes the copies an earlier version wrote out of Redis, and nothing else")
    void clearingTakesTheOldCopiesOutOfRedis() {
        LettuceConnectionFactory factory = new LettuceConnectionFactory("127.0.0.1",
                Integer.parseInt(System.getenv(REDIS_PORT)));
        factory.afterPropertiesSet();
        try {
            StringRedisTemplate strings = new StringRedisTemplate(factory);
            ContexaCacheProperties properties = new ContexaCacheProperties();
            properties.getRedis().setKeyPrefix("contexa:test:" + UUID.randomUUID() + ":");
            String prefix = properties.getRedis().getKeyPrefix();
            ContexaCacheService cache = new RedisContexaCacheService(properties, strings, mapper());
            String withHash = "{\"id\":7,\"username\":\"kim\",\"password\":\"" + HASH + "\"}";
            strings.opsForValue().set(prefix + SubjectCache.byId(7L), withHash);
            strings.opsForValue().set(prefix + SubjectCache.byName("kim"), withHash);
            strings.opsForValue().set(prefix + "policies:url:all", "[]");

            SubjectCache.clear(cache);

            assertThat(strings.hasKey(prefix + SubjectCache.byId(7L))).isFalse();
            assertThat(strings.hasKey(prefix + SubjectCache.byName("kim"))).isFalse();
            assertThat(strings.opsForValue().get(prefix + "policies:url:all")).isEqualTo("[]");
            strings.delete(prefix + "policies:url:all");
        } finally {
            factory.destroy();
        }
    }

    private static LocalContexaCacheService localCache() {
        LocalContexaCacheService cache = new LocalContexaCacheService(new ContexaCacheProperties(), mapper());
        cache.init();
        return cache;
    }

    private static ObjectMapper mapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    private static Authentication signedIn() {
        UserDto account = UserDto.builder().id(7L).username("kim").build();
        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(account, new HashSet<>());
        return new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities());
    }

    private static Users user() {
        return Users.builder().id(7L).username("kim").name("Kim").email("kim@example.test").password(HASH)
                .mfaEnabled(true).createdAt(LocalDateTime.of(2026, 1, 1, 9, 0))
                .updatedAt(LocalDateTime.of(2026, 2, 1, 9, 0)).build();
    }
}
