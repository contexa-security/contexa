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

import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreUnavailableException;
import io.lettuce.core.ClientOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * PR-84: Contexa's requests stop waiting a minute on Redis, and that is Contexa's own business: the application's
 * connection factory and its templates stay exactly as the application configured them.
 */
class ContexaRedisRequestPathTest {

    private ApplicationContextRunner runner(String... properties) {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class))
                .withPropertyValues(properties);
    }

    private static LettuceConnectionFactory bounded(ContexaRedisRequestPath path) {
        return (LettuceConnectionFactory) ReflectionTestUtils.getField(path, "bounded");
    }

    @Test
    @DisplayName("the distributed mode gives Contexa's templates the request path and leaves the application's alone")
    void theApplicationsRedisStaysTheApplications() {
        runner("contexa.infrastructure.mode=distributed").run(context -> {
            assertThat(context).hasNotFailed();
            RedisConnectionFactory application = context.getBean(RedisConnectionFactory.class);
            ContexaRedisRequestPath path = context.getBean(ContexaRedisRequestPath.class);

            assertThat(context.getBean(StringRedisTemplate.class).getConnectionFactory())
                    .as("a template the application asks for by type").isSameAs(application);
            assertThat(context.getBeansOfType(RedisConnectionFactory.class)).as("no second factory for the application to find").hasSize(1);
            assertThat(context.getBean("contexaStringRedisTemplate", StringRedisTemplate.class).getConnectionFactory())
                    .isSameAs(path.connections());
            for (String template : new String[]{"contexaGeneralRedisTemplate", "contexaEventRedisTemplate", "contexaTrustScoreRedisTemplate"}) {
                assertThat(context.getBean(template, RedisTemplate.class).getConnectionFactory()).as(template).isSameAs(path.connections());
            }
            LettuceClientConfiguration applications = ((LettuceConnectionFactory) application).getClientConfiguration();
            assertThat(applications.getCommandTimeout()).as("the application's wait").isEqualTo(Duration.ofMinutes(1));
            assertThat(applications.getClientOptions().map(ClientOptions::getDisconnectedBehavior)
                    .orElse(ClientOptions.DisconnectedBehavior.DEFAULT)).isEqualTo(ClientOptions.DisconnectedBehavior.DEFAULT);
        });
    }

    @Test
    @DisplayName("an application's own Redis gets no client of Contexa's while Contexa keeps its state in memory")
    void outsideTheDistributedModeNothingIsAdded() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(ContexaRedisRequestPath.class);
            assertThat(context.getBean("contexaStringRedisTemplate", StringRedisTemplate.class).getConnectionFactory())
                    .isSameAs(context.getBean(RedisConnectionFactory.class));
        });
    }

    @Test
    @DisplayName("a request's client waits a second and refuses a command while it is disconnected")
    void theRequestClientIsBounded() {
        runner("contexa.infrastructure.mode=distributed").run(context -> {
            LettuceClientConfiguration client = bounded(context.getBean(ContexaRedisRequestPath.class)).getClientConfiguration();

            assertThat(client.getCommandTimeout()).isEqualTo(Duration.ofSeconds(1));
            ClientOptions options = client.getClientOptions().orElseThrow();
            assertThat(options.getDisconnectedBehavior()).isEqualTo(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS);
            assertThat(options.getSocketOptions().getConnectTimeout()).isEqualTo(Duration.ofSeconds(1));
            assertThat(options.isAutoReconnect()).as("it comes back by itself").isTrue();
        });
    }

    @Test
    @DisplayName("a wait the application made shorter stays short")
    void aShorterWaitStays() {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.timeout=300ms").run(context ->
                assertThat(bounded(context.getBean(ContexaRedisRequestPath.class)).getClientConfiguration().getCommandTimeout())
                        .isEqualTo(Duration.ofMillis(300)));
    }

    @Test
    @DisplayName("the request's client reaches the same Redis the application does")
    void theSameRedis() {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.host=redis.shop", "spring.data.redis.port=6380",
                "spring.data.redis.database=3", "spring.data.redis.username=shop", "spring.data.redis.password=secret",
                "spring.data.redis.client-name=shop-client", "spring.data.redis.ssl.enabled=true").run(context -> {
                    LettuceConnectionFactory copy = bounded(context.getBean(ContexaRedisRequestPath.class));

                    assertThat(copy.getHostName()).isEqualTo("redis.shop");
                    assertThat(copy.getPort()).isEqualTo(6380);
                    assertThat(copy.getDatabase()).isEqualTo(3);
                    assertThat(copy.getStandaloneConfiguration().getUsername()).isEqualTo("shop");
                    assertThat(copy.getPassword()).isEqualTo("secret");
                    assertThat(copy.getClientName()).isEqualTo("shop-client");
                    assertThat(copy.getClientConfiguration().isUseSsl()).isTrue();
                });
    }

    @Test
    @DisplayName("Sentinel is followed as the application follows it")
    void sentinelIsFollowed() {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.sentinel.master=main",
                "spring.data.redis.sentinel.nodes=127.0.0.1:26379").run(context -> {
                    LettuceConnectionFactory copy = bounded(context.getBean(ContexaRedisRequestPath.class));

                    assertThat(copy.isRedisSentinelAware()).isTrue();
                    assertThat(copy.getSentinelConfiguration().getMaster().getName()).isEqualTo("main");
                });
    }

    @Test
    @DisplayName("a cluster keeps the application's client: it is not supported in this release, and only the gate applies")
    void aClusterKeepsTheApplicationsClient() {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.cluster.nodes=127.0.0.1:7000").run(context ->
                assertThat(bounded(context.getBean(ContexaRedisRequestPath.class))).isNull());
    }

    @Test
    @DisplayName("while the gate is down a request does not reach Redis; a thread of the engine still does")
    void theGateStopsRequestsOnly() throws Exception {
        ContexaStores stores = new ContexaStores();
        RedisConnectionFactory application = mock(RedisConnectionFactory.class);
        ContexaRedisRequestPath path = new ContexaRedisRequestPath(application, stores.redis());
        path.afterPropertiesSet();
        stores.redis().fail(new QueryTimeoutException("no answer"));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        try {
            assertThatThrownBy(() -> path.connections().getConnection()).isInstanceOf(StoreUnavailableException.class);
            verify(application, never()).getConnection();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }

        path.connections().getConnection();

        verify(application).getConnection();
        stores.destroy();
    }
}
