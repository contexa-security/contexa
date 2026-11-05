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
package io.contexa.contexaidentity.security.zerotrust;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import io.contexa.contexacommon.cache.ContexaCacheProperties;
import io.contexa.contexacommon.cache.RedisContexaCacheService;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.ServletWebServerFactoryAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;

/**
 * PR-84 on a real Tomcat with a real Redis that stops and freezes, on the wiring the application gets: Spring Boot's
 * client with its one-minute wait, and Contexa's templates on top of it. A request of the application never waits for
 * that minute, a page no decision protects included; a restriction read before the outage stays in force; a user without
 * one goes on; and everything comes back by itself.
 */
@SpringBootTest(classes = RedisOutageTomcatTest.Web.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "contexa.infrastructure.mode=distributed")
class RedisOutageTomcatTest {

    private static final String USER_HEADER = "X-Outage-User";
    /** The wait the specification gives a request, with room for a machine busy with the rest of the test. */
    private static final Duration ANSWER_LIMIT = Duration.ofSeconds(2);
    private static final int REDIS_PORT = freePort();

    private static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine"))
            .withExposedPorts(6379)
            .withCreateContainerCmdModifier(command -> {
                command.withName("p3infra-redis-" + UUID.randomUUID());
                command.getHostConfig().withPortBindings(new PortBinding(Ports.Binding.bindPort(REDIS_PORT), ExposedPort.tcp(6379)));
            });

    static {
        REDIS.start();
    }

    @DynamicPropertySource
    static void redis(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", () -> "127.0.0.1");
        registry.add("spring.data.redis.port", () -> REDIS_PORT);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private ZeroTrustActionRedisRepository decisions;

    @Autowired
    private ContexaStores stores;

    @Autowired
    @Qualifier("contexaStringRedisTemplate")
    private StringRedisTemplate strings;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private record Answer(int status, String body, Duration took) {
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String newUser() {
        return "outage-" + UUID.randomUUID();
    }

    private Answer get(String path, String user) throws Exception {
        long began = System.nanoTime();
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header(USER_HEADER, user).header("Accept", "text/html").timeout(Duration.ofSeconds(90)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Answer(response.statusCode(), response.body(), Duration.ofNanos(System.nanoTime() - began));
    }

    private static void assertInTime(Answer answer) {
        assertThat(answer.took()).as("a request does not wait for a store that does not answer").isLessThan(ANSWER_LIMIT);
    }

    private void stopRedis() {
        REDIS.getDockerClient().stopContainerCmd(REDIS.getContainerId()).exec();
    }

    private void startRedis() {
        REDIS.getDockerClient().startContainerCmd(REDIS.getContainerId()).exec();
    }

    private void freezeRedis() {
        REDIS.getDockerClient().pauseContainerCmd(REDIS.getContainerId()).exec();
    }

    private void thawRedis() {
        REDIS.getDockerClient().unpauseContainerCmd(REDIS.getContainerId()).exec();
    }

    private void awaitRedisBack() {
        await().atMost(Duration.ofSeconds(30)).pollInterval(Duration.ofMillis(200)).until(() -> {
            try {
                return !stores.redis().isDown() && get("/page", newUser()).status() == 200;
            } catch (Exception notYet) {
                return false;
            }
        });
    }

    @AfterEach
    void redisRuns() {
        var state = REDIS.getDockerClient().inspectContainerCmd(REDIS.getContainerId()).exec().getState();
        if (Boolean.TRUE.equals(state.getPaused())) {
            thawRedis();
        } else if (!Boolean.TRUE.equals(state.getRunning())) {
            startRedis();
        }
        awaitRedisBack();
    }

    @Test
    @DisplayName("a stopped Redis holds no request and lifts no restriction, and all of it comes back by itself")
    void aStoppedRedis() throws Exception {
        String blocked = newUser();
        String challenged = newUser();
        String free = newUser();
        decisions.setBlockedFlag(blocked);
        decisions.saveAction(challenged, ZeroTrustAction.CHALLENGE, Map.of());
        assertThat(get("/page", blocked).status()).as("the blocked user is stopped before the outage").isEqualTo(302);
        assertThat(get("/action", challenged).body()).isEqualTo("CHALLENGE");
        assertThat(get("/page", free).status()).isEqualTo(200);

        stopRedis();

        for (int request = 0; request < 3; request++) {
            Answer stoppedUser = get("/page", blocked);
            assertInTime(stoppedUser);
            assertThat(stoppedUser.status()).as("a BLOCK stays in force").isEqualTo(302);

            Answer challenge = get("/action", challenged);
            assertInTime(challenge);
            assertThat(challenge.body()).as("a CHALLENGE stays in force").isEqualTo("CHALLENGE");

            Answer page = get("/page", free);
            assertInTime(page);
            assertThat(page.status()).as("a page no decision protects answers").isEqualTo(200);

            Answer cached = get("/cached", free);
            assertInTime(cached);
            assertThat(cached.status()).as("a cache Redis does not take is no server error").isEqualTo(200);
            assertThat(cached.body()).isEqualTo("loaded");
        }
        assertThat(stores.redis().isDown()).isTrue();

        startRedis();
        awaitRedisBack();

        assertThat(get("/page", blocked).status()).as("the BLOCK is read from Redis again").isEqualTo(302);
        assertThat(get("/page", free).status()).as("nobody else was stopped by the outage").isEqualTo(200);
        assertThat(strings.opsForValue().get("a key nobody wrote")).isNull();
    }

    @Test
    @DisplayName("a block this server never read is found in the database's record")
    void aBlockThisServerNeverRead() throws Exception {
        String recorded = "recorded-" + UUID.randomUUID();
        decisions.setBlockRecord(user -> user.equals(recorded));
        try {
            stopRedis();

            Answer answer = get("/page", recorded);

            assertInTime(answer);
            assertThat(answer.status()).isEqualTo(302);
            assertThat(get("/page", newUser()).status()).as("the record stops nobody else").isEqualTo(200);
        } finally {
            decisions.setBlockRecord(user -> false);
        }
    }

    @Test
    @DisplayName("a frozen Redis, which takes commands and answers none, costs one request about a second")
    void aFrozenRedis() throws Exception {
        String blocked = newUser();
        decisions.setBlockedFlag(blocked);
        assertThat(get("/page", blocked).status()).isEqualTo(302);

        freezeRedis();

        Answer first = get("/page", newUser());
        assertInTime(first);
        assertThat(first.status()).isEqualTo(200);
        assertThat(first.took()).as("the first request found the outage").isGreaterThan(Duration.ofMillis(500));

        Answer next = get("/page", newUser());
        assertThat(next.status()).isEqualTo(200);
        assertThat(next.took()).as("the gate is down: nobody waits any more").isLessThan(Duration.ofMillis(500));
        assertThat(get("/page", blocked).status()).as("a BLOCK stays in force").isEqualTo(302);

        thawRedis();
        awaitRedisBack();
    }

    @Test
    @DisplayName("the engine's threads keep the application's client: a short outage costs them no work")
    void theEnginesThreadsKeepTheirWait() throws Exception {
        String key = "engine-" + UUID.randomUUID();
        strings.opsForValue().set(key, "kept");
        stopRedis();
        assertThat(get("/page", newUser()).status()).isEqualTo(200);

        CompletableFuture<String> enginesRead = CompletableFuture.supplyAsync(() -> strings.opsForValue().get(key));
        Thread.sleep(1500);
        assertThat(enginesRead).as("it waits; it was not refused at once as a request is").isNotDone();

        startRedis();

        assertThat(enginesRead.get(45, TimeUnit.SECONDS)).isEqualTo("kept");
    }

    /** Signs the request in as the user the header names, as the application's security chain would. */
    static final class SignIn extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            SecurityContextHolder.setContext(new SecurityContextImpl(UsernamePasswordAuthenticationToken.authenticated(
                    request.getHeader(USER_HEADER), null, List.of())));
            try {
                chain.doFilter(request, response);
            } finally {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @RestController
    static class Pages {

        private static final TypeReference<String> TEXT = new TypeReference<>() {
        };

        private final ZeroTrustActionRedisRepository decisions;
        private final RedisContexaCacheService cache;

        Pages(ZeroTrustActionRedisRepository decisions, RedisContexaCacheService cache) {
            this.decisions = decisions;
            this.cache = cache;
        }

        @GetMapping("/page")
        String page() {
            return "page";
        }

        @GetMapping("/cached")
        String cached() {
            return cache.get("user_details:" + UUID.randomUUID(), () -> "loaded", TEXT, "users");
        }

        @GetMapping("/action")
        String action(@RequestHeader(USER_HEADER) String user) {
            return decisions.getCurrentAction(user, "a-context").name();
        }
    }

    @SpringBootConfiguration
    @ImportAutoConfiguration({ServletWebServerFactoryAutoConfiguration.class, DispatcherServletAutoConfiguration.class,
            WebMvcAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class, JacksonAutoConfiguration.class,
            RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class})
    static class Web {

        @Bean
        ContexaStores contexaStores() {
            return new ContexaStores();
        }

        @Bean
        ZeroTrustActionRedisRepository decisions(
                @Qualifier("contexaGeneralRedisTemplate") RedisTemplate<String, Object> objects,
                @Qualifier("contexaStringRedisTemplate") StringRedisTemplate strings) {
            return new ZeroTrustActionRedisRepository(objects, strings);
        }

        @Bean
        RedisContexaCacheService cache(@Qualifier("contexaStringRedisTemplate") StringRedisTemplate strings) {
            return new RedisContexaCacheService(new ContexaCacheProperties(), strings, new ObjectMapper());
        }

        @Bean
        Pages pages(ZeroTrustActionRedisRepository decisions, RedisContexaCacheService cache) {
            return new Pages(decisions, cache);
        }

        @Bean
        FilterRegistrationBean<SignIn> signIn() {
            FilterRegistrationBean<SignIn> registration = new FilterRegistrationBean<>(new SignIn());
            registration.setOrder(1);
            return registration;
        }

        @Bean
        FilterRegistrationBean<ZeroTrustAccessControlFilter> zeroTrust(ZeroTrustActionRedisRepository decisions) {
            FilterRegistrationBean<ZeroTrustAccessControlFilter> registration = new FilterRegistrationBean<>(
                    new ZeroTrustAccessControlFilter(decisions, mock(AuthResponseWriter.class), null, null, null, null, 2));
            registration.setOrder(2);
            return registration;
        }
    }
}
