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

import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacommon.store.StoreGate;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.resource.Delay;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisClusterConnection;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisSentinelConnection;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.lang.Nullable;
import org.springframework.util.ClassUtils;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * How Contexa's Redis templates reach Redis. Spring Boot's client waits a minute for a command, and queues commands while
 * it is disconnected, so a stopped Redis held every request that reads a decision, the pages no decision protects
 * included, a minute for each read (PR-84).
 * <p>
 * The application's client is the application's: its settings are not touched. A request of the application reaches
 * Redis through a client of Contexa's own, made from the same connection settings, that refuses a command at once while
 * it is disconnected and waits about a second for one that does not answer. The engine's threads keep the application's
 * client and its waits, which let a short outage pass without losing their work. While the gate is down a request does
 * not even try. A cluster, a socket or a client other than Lettuce gets no client of Contexa's and keeps only the gate.
 */
public final class ContexaRedisRequestPath implements InitializingBean, DisposableBean {

    /** The wait for one command on a request; a request meets it once, as the first failure lowers the gate. */
    public static final Duration REQUEST_WAIT = Duration.ofSeconds(1);
    /**
     * Spring Boot's client backs off up to thirty seconds, too long for a request path to stay away from a Redis that came
     * back. The client logs every attempt, so it does not try every second either.
     */
    private static final Delay RECONNECT_DELAY = Delay.exponential(Duration.ofMillis(500), Duration.ofSeconds(5), 2,
            TimeUnit.MILLISECONDS);
    private static final String LETTUCE = "io.lettuce.core.RedisClient";

    private final RedisConnectionFactory application;
    private final StoreGate gate;
    @Nullable
    private final LettuceConnectionFactory bounded;
    private final RedisConnectionFactory connections = new RoutedConnections();

    public ContexaRedisRequestPath(RedisConnectionFactory application, StoreGate gate) {
        this.application = application;
        this.gate = gate;
        this.bounded = ClassUtils.isPresent(LETTUCE, getClass().getClassLoader()) ? LettuceCopies.of(application) : null;
    }

    /** What Contexa's templates connect through. */
    public RedisConnectionFactory connections() {
        return connections;
    }

    public StoreGate gate() {
        return gate;
    }

    @Override
    public void afterPropertiesSet() {
        if (bounded != null) {
            bounded.afterPropertiesSet();
        }
        gate.watchWith(this::ping);
    }

    @Override
    public void destroy() {
        if (bounded != null) {
            bounded.destroy();
        }
    }

    private RedisConnectionFactory requestPath() {
        return bounded != null ? bounded : application;
    }

    private void ping() {
        try (RedisConnection connection = requestPath().getConnection()) {
            connection.ping();
        }
    }

    private final class RoutedConnections implements RedisConnectionFactory {

        @Override
        public RedisConnection getConnection() {
            if (!RequestPathScope.onRequestThread()) {
                return application.getConnection();
            }
            if (gate.isDown()) {
                throw gate.unavailable();
            }
            return requestPath().getConnection();
        }

        @Override
        public RedisClusterConnection getClusterConnection() {
            return application.getClusterConnection();
        }

        @Override
        public boolean getConvertPipelineAndTxResults() {
            return application.getConvertPipelineAndTxResults();
        }

        @Override
        public RedisSentinelConnection getSentinelConnection() {
            return application.getSentinelConnection();
        }

        @Override
        @Nullable
        public DataAccessException translateExceptionIfPossible(RuntimeException failure) {
            return application.translateExceptionIfPossible(failure);
        }
    }

    /** Kept apart so that an application on another client never loads a Lettuce type. */
    private static final class LettuceCopies {

        @Nullable
        static LettuceConnectionFactory of(RedisConnectionFactory application) {
            if (!(application instanceof LettuceConnectionFactory lettuce) || lettuce.isClusterAware()
                    || lettuce.getSocketConfiguration() != null) {
                return null;
            }
            LettuceClientConfiguration client = bounded(lettuce.getClientConfiguration());
            return lettuce.isRedisSentinelAware()
                    ? new LettuceConnectionFactory(lettuce.getSentinelConfiguration(), client)
                    : new LettuceConnectionFactory(lettuce.getStandaloneConfiguration(), client);
        }

        private static LettuceClientConfiguration bounded(LettuceClientConfiguration source) {
            Duration wait = source.getCommandTimeout().compareTo(REQUEST_WAIT) < 0 ? source.getCommandTimeout() : REQUEST_WAIT;
            ClientOptions options = source.getClientOptions().orElseGet(ClientOptions::create);
            LettuceClientConfiguration.LettuceClientConfigurationBuilder copy = LettuceClientConfiguration.builder();
            if (source.isUseSsl()) {
                LettuceClientConfiguration.LettuceSslClientConfigurationBuilder tls = copy.useSsl().verifyPeer(source.getVerifyMode());
                if (source.isStartTls()) {
                    tls.startTls();
                }
            }
            source.getClientName().ifPresent(copy::clientName);
            source.getReadFrom().ifPresent(copy::readFrom);
            source.getRedisCredentialsProviderFactory().ifPresent(copy::redisCredentialsProviderFactory);
            source.getClientResources().ifPresent(resources -> copy.clientResources(
                    resources.mutate().reconnectDelay(RECONNECT_DELAY).build()));
            return copy.clientOptions(options.mutate()
                            .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
                            .socketOptions(options.getSocketOptions().mutate().connectTimeout(wait).build())
                            .timeoutOptions(TimeoutOptions.enabled(wait))
                            .build())
                    .commandTimeout(wait)
                    .shutdownTimeout(source.getShutdownTimeout())
                    .shutdownQuietPeriod(source.getShutdownQuietPeriod())
                    .build();
        }
    }
}
