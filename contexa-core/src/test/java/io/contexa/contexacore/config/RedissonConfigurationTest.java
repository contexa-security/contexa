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
package io.contexa.contexacore.config;

import org.junit.jupiter.api.Test;
import org.redisson.config.Config;
import org.springframework.boot.autoconfigure.data.redis.RedisConnectionDetails;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.ssl.SslBundle;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Contexa's Redisson client connects to the Redis the application describes, with everything the application says about it, and does not
 * connect before it is used.
 */
class RedissonConfigurationTest {

    private static RedisConnectionDetails standalone(String user, String password, int database, boolean tls) {
        return new RedisConnectionDetails() {
            @Override
            public String getUsername() {
                return user;
            }

            @Override
            public String getPassword() {
                return password;
            }

            @Override
            public Standalone getStandalone() {
                return Standalone.of("redis.example", 6380, database, tls ? mock(SslBundle.class) : null);
            }
        };
    }

    @Test
    void thePasswordTheDatabaseTheUserAndTlsOfTheApplicationsRedisAreUsed() throws Exception {
        String yaml = RedissonConfiguration.configFor(standalone("svc", "s3cret", 4, true), new RedisProperties()).toYAML();

        assertThat(yaml).contains("rediss://redis.example:6380").contains("password: \"s3cret\"").contains("username: \"svc\"")
                .contains("database: 4");
    }

    @Test
    void aRedisWithoutPasswordOrTlsIsReachedAsBefore() throws Exception {
        String yaml = RedissonConfiguration.configFor(standalone(null, null, 0, false), new RedisProperties()).toYAML();

        assertThat(yaml).contains("redis://redis.example:6380").doesNotContain("rediss://").contains("database: 0");
    }

    @Test
    void thePropertiesAreUsedWhenSpringBootMadeNoConnectionDetails() throws Exception {
        RedisProperties properties = new RedisProperties();
        properties.setHost("props.example");
        properties.setPort(6390);
        properties.setPassword("pw");
        properties.setDatabase(2);
        properties.getSsl().setEnabled(true);

        String yaml = RedissonConfiguration.configFor(null, properties).toYAML();

        assertThat(yaml).contains("rediss://props.example:6390").contains("password: \"pw\"").contains("database: 2");
    }

    @Test
    void sentinelAndClusterAreReadToo() throws Exception {
        RedisConnectionDetails sentinel = new RedisConnectionDetails() {
            @Override
            public Sentinel getSentinel() {
                return new Sentinel() {
                    @Override
                    public int getDatabase() {
                        return 3;
                    }

                    @Override
                    public String getMaster() {
                        return "mymaster";
                    }

                    @Override
                    public List<Node> getNodes() {
                        return List.of(new Node("s1.example", 26379), new Node("s2.example", 26379));
                    }

                    @Override
                    public String getUsername() {
                        return null;
                    }

                    @Override
                    public String getPassword() {
                        return "sentinel-pw";
                    }
                };
            }
        };
        RedisConnectionDetails cluster = new RedisConnectionDetails() {
            @Override
            public Cluster getCluster() {
                return () -> List.of(new Node("c1.example", 7000), new Node("c2.example", 7001));
            }
        };

        assertThat(RedissonConfiguration.configFor(sentinel, new RedisProperties()).toYAML()).contains("mymaster")
                .contains("redis://s1.example:26379").contains("redis://s2.example:26379").contains("database: 3");
        assertThat(RedissonConfiguration.configFor(cluster, new RedisProperties()).toYAML()).contains("redis://c1.example:7000")
                .contains("redis://c2.example:7001");
    }

    @Test
    void itConnectsWhenFirstUsedNotWhenTheApplicationStarts() throws Exception {
        Config config = RedissonConfiguration.configFor(standalone(null, null, 0, false), new RedisProperties());

        assertThat(config.isLazyInitialization()).as("a Redis that is down at start must not stop the application").isTrue();
    }

    @Test
    void aDefaultLocaleWithOtherDigitsDoesNotChangeTheAddress() throws Exception {
        Locale before = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar-EG"));

            assertThat(RedissonConfiguration.configFor(standalone(null, null, 0, false), new RedisProperties()).toYAML())
                    .contains("redis://redis.example:6380");
        } finally {
            Locale.setDefault(before);
        }
    }
}
