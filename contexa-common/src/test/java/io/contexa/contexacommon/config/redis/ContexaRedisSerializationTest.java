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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.domain.SecurityEvent;
import org.example.untrusted.UntrustedPayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ContexaRedisSerializationTest {

    private static final String UNTRUSTED_TYPE = "org.example.untrusted.UntrustedPayload";

    private final RedisConnectionFactory connectionFactory = mock(RedisConnectionFactory.class);

    @Test
    @DisplayName("generalRedisTemplate round-trips the value types Contexa stores in Redis")
    void generalTemplateRoundTripsStoredValueTypes() {
        RedisSerializer<Object> serializer = generalSerializer();
        Instant now = Instant.parse("2026-10-02T10:15:30Z");
        UUID id = UUID.fromString("0f5b8c1e-7d4a-4c1b-9b0e-2f6f4d1e7a10");

        StoredSessionData session = new StoredSessionData();
        session.setUserId("user-1");
        session.setAuthorities(new ArrayList<>(List.of("ROLE_USER", "ROLE_ADMIN")));
        session.setExpiresAt(now);
        session.setAttributes(new HashMap<>(Map.of("risk", 0.4d, "device", "laptop")));

        Map<String, Object> value = new HashMap<>();
        value.put("text", "plain");
        value.put("count", 42L);
        value.put("small", 7);
        value.put("score", 0.75d);
        value.put("flag", true);
        value.put("at", now);
        value.put("amount", new BigDecimal("12.50"));
        value.put("id", id);
        value.put("date", Date.from(now));
        value.put("tags", new ArrayList<>(List.of("a", "b")));
        value.put("ranges", new String[]{"10.0.0.0/8", "192.168.0.0/16"});
        value.put("hours", new Integer[]{9, 18});
        value.put("nested", new LinkedHashMap<>(Map.of("key", "value")));
        value.put("unique", new LinkedHashSet<>(List.of("x", "y")));
        value.put("concurrent", new ConcurrentHashMap<>(Map.of("c", 1)));
        value.put("session", session);

        Object restored = serializer.deserialize(serializer.serialize(value));

        assertThat(restored).isInstanceOf(HashMap.class);
        Map<?, ?> map = (Map<?, ?>) restored;
        assertThat(map.get("text")).isEqualTo("plain");
        assertThat(map.get("count")).isEqualTo(42L);
        assertThat(map.get("small")).isEqualTo(7);
        assertThat(map.get("score")).isEqualTo(0.75d);
        assertThat(map.get("flag")).isEqualTo(true);
        assertThat(map.get("at")).isEqualTo(now);
        assertThat(map.get("amount")).isEqualTo(new BigDecimal("12.50"));
        assertThat(map.get("id")).isEqualTo(id);
        assertThat(map.get("date")).isEqualTo(Date.from(now));
        assertThat(map.get("tags")).isEqualTo(List.of("a", "b"));
        assertThat((String[]) map.get("ranges")).containsExactly("10.0.0.0/8", "192.168.0.0/16");
        assertThat((Integer[]) map.get("hours")).containsExactly(9, 18);
        assertThat(map.get("nested")).isEqualTo(Map.of("key", "value"));
        assertThat(map.get("unique")).isInstanceOf(LinkedHashSet.class);
        assertThat(map.get("concurrent")).isInstanceOf(ConcurrentHashMap.class).isEqualTo(Map.of("c", 1));
        assertThat(map.get("session")).isInstanceOf(StoredSessionData.class);
        StoredSessionData restoredSession = (StoredSessionData) map.get("session");
        assertThat(restoredSession.getUserId()).isEqualTo("user-1");
        assertThat(restoredSession.getAuthorities()).containsExactly("ROLE_USER", "ROLE_ADMIN");
        assertThat(restoredSession.getExpiresAt()).isEqualTo(now);
        assertThat(restoredSession.getAttributes()).isEqualTo(Map.of("risk", 0.4d, "device", "laptop"));
    }

    @Test
    @DisplayName("generalRedisTemplate keeps the existing WRAPPER_ARRAY wire format and reads data written before the allowlist")
    void generalTemplateKeepsExistingWireFormat() {
        RedisSerializer<Object> serializer = generalSerializer();
        GenericJackson2JsonRedisSerializer legacySerializer = new GenericJackson2JsonRedisSerializer(legacyGeneralObjectMapper());
        Map<String, Object> value = new HashMap<>();
        value.put("userId", "user-1");
        value.put("updateCount", 3L);
        value.put("frequentPaths", new String[]{"/api/orders"});
        value.put("elementFrequencies", new HashMap<>(Map.of("GET /api/orders", 5)));

        byte[] written = serializer.serialize(value);
        byte[] legacyWritten = legacySerializer.serialize(value);

        assertThat(new String(written, StandardCharsets.UTF_8)).startsWith("[\"java.util.HashMap\",");
        assertThat(written).isEqualTo(legacyWritten);
        Map<?, ?> restored = (Map<?, ?>) serializer.deserialize(legacyWritten);
        assertThat(restored.get("userId")).isEqualTo("user-1");
        assertThat(restored.get("updateCount")).isEqualTo(3L);
        assertThat((String[]) restored.get("frequentPaths")).containsExactly("/api/orders");
        assertThat(restored.get("elementFrequencies")).isEqualTo(Map.of("GET /api/orders", 5));
    }

    @Test
    @DisplayName("PROPERTY-inclusion serializer used by securityEventRedisTemplate accepts Contexa and JDK types")
    void propertyInclusionSerializerAcceptsAllowedTypes() {
        RedisSerializer<Object> serializer = propertyInclusionSerializer();
        Instant now = Instant.parse("2026-10-02T10:15:30Z");
        StoredSessionData session = new StoredSessionData();
        session.setUserId("user-1");
        session.setAuthorities(new ArrayList<>(List.of("ROLE_USER")));
        session.setExpiresAt(now);
        Map<String, Object> value = new HashMap<>();
        value.put("session", session);
        value.put("count", 3L);
        value.put("tags", new ArrayList<>(List.of("geo")));

        byte[] written = serializer.serialize(value);
        Map<?, ?> restored = (Map<?, ?>) serializer.deserialize(written);

        assertThat(new String(written, StandardCharsets.UTF_8)).contains("\"@class\":\"java.util.HashMap\"");
        assertThat(restored.get("count")).isEqualTo(3L);
        assertThat(restored.get("tags")).isEqualTo(List.of("geo"));
        assertThat(((StoredSessionData) restored.get("session")).getAuthorities()).containsExactly("ROLE_USER");

        String securityEvent = "{\"@class\":\"io.contexa.contexacommon.domain.SecurityEvent\","
                + "\"eventId\":\"event-1\",\"source\":\"IAM\",\"severity\":\"HIGH\",\"userId\":\"user-1\","
                + "\"timestamp\":[2026,10,2,10,15,30],"
                + "\"metadata\":{\"@class\":\"java.util.HashMap\",\"attempts\":3}}";
        Object event = serializer.deserialize(securityEvent.getBytes(StandardCharsets.UTF_8));

        assertThat(event).isInstanceOf(SecurityEvent.class);
        SecurityEvent restoredEvent = (SecurityEvent) event;
        assertThat(restoredEvent.getEventId()).isEqualTo("event-1");
        assertThat(restoredEvent.getSource()).isEqualTo(SecurityEvent.EventSource.IAM);
        assertThat(restoredEvent.getSeverity()).isEqualTo(SecurityEvent.Severity.HIGH);
        assertThat(restoredEvent.getTimestamp()).isEqualTo(LocalDateTime.of(2026, 10, 2, 10, 15, 30));
        assertThat(restoredEvent.getMetadata()).isEqualTo(Map.of("attempts", 3));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "[\"java.net.URL\",\"http://example.com\"]",
            "[\"java.util.HashMap\",{\"payload\":[\"java.net.URL\",\"http://example.com\"]}]",
            "[\"java.util.logging.FileHandler\",{}]",
            "[\"java.util.Timer\",{}]",
            "[\"java.util.ArrayList<java.net.URL>\",[\"http://example.com\"]]",
            "[\"[Ljava.net.URL;\",[\"http://example.com\"]]",
            "[\"" + UNTRUSTED_TYPE + "\",{\"command\":\"calc\"}]",
            "[\"java.util.ArrayList\",[[\"" + UNTRUSTED_TYPE + "\",{\"command\":\"calc\"}]]]"
    })
    @DisplayName("generalRedisTemplate rejects type ids outside the allowlist")
    void generalTemplateRejectsTypesOutsideAllowlist(String json) {
        RedisSerializer<Object> serializer = generalSerializer();
        int instantiations = UntrustedPayload.INSTANTIATIONS.get();

        assertThatThrownBy(() -> serializer.deserialize(json.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(SerializationException.class);
        assertThat(UntrustedPayload.INSTANTIATIONS.get()).isEqualTo(instantiations);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"@class\":\"" + UNTRUSTED_TYPE + "\",\"command\":\"calc\"}",
            "{\"@class\":\"java.util.HashMap\",\"payload\":{\"@class\":\"" + UNTRUSTED_TYPE + "\",\"command\":\"calc\"}}"
    })
    @DisplayName("a root-level @class hint cannot bypass the allowlist")
    void rootTypeHintCannotBypassAllowlist(String json) {
        int instantiations = UntrustedPayload.INSTANTIATIONS.get();
        byte[] source = json.getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> propertyInclusionSerializer().deserialize(source))
                .isInstanceOf(SerializationException.class);
        assertThatThrownBy(() -> generalSerializer().deserialize(source))
                .isInstanceOf(SerializationException.class);
        assertThat(UntrustedPayload.INSTANTIATIONS.get()).isEqualTo(instantiations);
    }

    @Test
    @DisplayName("generalRedisTemplate is a fallback: it serves unqualified injection only when the application defines no RedisTemplate<String, Object>")
    void generalTemplateIsFallbackForUnqualifiedInjection() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withBean(RedisConnectionFactory.class, () -> connectionFactory)
                .withConfiguration(AutoConfigurations.of(CommonRedisAutoConfiguration.class))
                .withUserConfiguration(InjectionProbeConfiguration.class);

        runner.run(context -> {
            assertThat(context).hasNotFailed();
            InjectionProbe probe = context.getBean(InjectionProbe.class);
            Object general = context.getBean("generalRedisTemplate");
            assertThat(probe.unqualified()).isSameAs(general);
            assertThat(probe.provided()).isSameAs(general);
            assertThat(probe.qualified()).isSameAs(general);
        });

        runner.withUserConfiguration(ApplicationRedisTemplateConfiguration.class).run(context -> {
            assertThat(context).hasNotFailed();
            InjectionProbe probe = context.getBean(InjectionProbe.class);
            Object application = context.getBean("applicationRedisTemplate");
            assertThat(probe.unqualified()).isSameAs(application);
            assertThat(probe.provided()).isSameAs(application);
            assertThat(probe.qualified()).isSameAs(context.getBean("generalRedisTemplate"));
        });
    }

    @SuppressWarnings("unchecked")
    private RedisSerializer<Object> generalSerializer() {
        RedisTemplate<String, Object> template = new CommonRedisAutoConfiguration().generalRedisTemplate(connectionFactory);
        return (RedisSerializer<Object>) template.getValueSerializer();
    }

    private RedisSerializer<Object> propertyInclusionSerializer() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        return new ContexaJsonRedisSerializer(
                ContexaJsonRedisSerializer.activateDefaultTyping(objectMapper, JsonTypeInfo.As.PROPERTY));
    }

    private ObjectMapper legacyGeneralObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        objectMapper.activateDefaultTyping(
                BasicPolymorphicTypeValidator.builder().allowIfSubType(Object.class).build(),
                ObjectMapper.DefaultTyping.NON_FINAL);
        return objectMapper;
    }

    public static class StoredSessionData {

        private String userId;
        private List<String> authorities;
        private Instant expiresAt;
        private Map<String, Object> attributes;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public List<String> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<String> authorities) {
            this.authorities = authorities;
        }

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }

        public Map<String, Object> getAttributes() {
            return attributes;
        }

        public void setAttributes(Map<String, Object> attributes) {
            this.attributes = attributes;
        }
    }

    record InjectionProbe(Object unqualified, Object provided, Object qualified) {
    }

    @Configuration(proxyBeanMethods = false)
    static class InjectionProbeConfiguration {

        @Bean
        InjectionProbe injectionProbe(
                RedisTemplate<String, Object> unqualified,
                ObjectProvider<RedisTemplate<String, Object>> provider,
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> qualified) {
            return new InjectionProbe(unqualified, provider.getIfAvailable(), qualified);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationRedisTemplateConfiguration {

        @Bean
        RedisTemplate<String, Object> applicationRedisTemplate(RedisConnectionFactory connectionFactory) {
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(connectionFactory);
            return template;
        }
    }
}
