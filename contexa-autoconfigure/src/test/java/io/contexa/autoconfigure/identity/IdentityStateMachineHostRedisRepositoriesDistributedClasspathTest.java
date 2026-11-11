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
package io.contexa.autoconfigure.identity;

import io.contexa.autoconfigure.hostredis.HostDevice;
import io.contexa.autoconfigure.hostredis.HostDeviceRepository;
import io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.config.kyro.MfaKryoStateMachineSerialisationService;
import io.contexa.contexaidentity.security.statemachine.core.persist.ApplicationStateMachineKeyspaces;
import io.contexa.contexaidentity.security.statemachine.core.persist.ExpiringRedisRepositoryStateMachinePersist;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineServiceImpl;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.repository.support.RedisRepositoryFactoryBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.statemachine.StateMachineContext;
import org.springframework.statemachine.StateMachinePersist;
import org.springframework.statemachine.data.redis.RedisStateMachineRepository;
import org.springframework.statemachine.support.DefaultExtendedState;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;

/**
 * A host application with Redis repositories of its own ({@code @RedisHash} and a {@code CrudRepository}) that turns on the
 * distributed mode, on a real Redis: Spring Boot still makes the application's repositories, no bean of the application
 * changes its name or its type, and Contexa keeps its MFA flows under the keys, in the form, that the repositories Spring
 * Data enabled for Spring Statemachine's package kept them. Runs in the task distributedClasspathTest, whose class path has
 * Redisson and Spring Statemachine's Redis repositories. CONTEXA_TEST_REDIS_PORT: a Redis of the test; it removes only the
 * keys and the set members it wrote.
 */
@EnabledIfEnvironmentVariable(named = IdentityStateMachineHostRedisRepositoriesDistributedClasspathTest.PORT, matches = "[0-9]+")
class IdentityStateMachineHostRedisRepositoriesDistributedClasspathTest {

    static final String PORT = "CONTEXA_TEST_REDIS_PORT";
    private static final String HOST = "CONTEXA_TEST_REDIS_HOST";
    private static final String FLOWS = "RedisRepositoryStateMachine";
    private static final String DEVICES = "host-devices";
    private static final String APPLICATION = "devices-app";
    private static final Duration TTL = Duration.ofMinutes(30);

    private static String redisHost;
    private static int redisPort;
    private static LettuceConnectionFactory connections;
    private static StringRedisTemplate redis;

    private final List<String> keysToRemove = new ArrayList<>();
    private final Map<String, List<String>> membersToRemove = new LinkedHashMap<>();

    @BeforeAll
    static void connect() {
        String host = System.getenv(HOST);
        redisHost = host == null || host.isBlank() ? "127.0.0.1" : host.trim();
        redisPort = Integer.parseInt(System.getenv(PORT).trim());
        assertThat(redisPort).as("a Redis of the test, not one on 6379").isNotEqualTo(6379);
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(redisHost, redisPort));
        connections.afterPropertiesSet();
        redis = new StringRedisTemplate(connections);
    }

    @AfterAll
    static void disconnect() {
        if (connections != null) {
            connections.destroy();
        }
        if (HostApplicationWithItsOwnTemplate.connections != null) {
            HostApplicationWithItsOwnTemplate.connections.destroy();
        }
    }

    @AfterEach
    void removeWhatThisTestWrote() {
        keysToRemove.forEach(redis::delete);
        membersToRemove.forEach((set, members) -> redis.opsForSet().remove(set, members.toArray()));
    }

    @Test
    @DisplayName("the application's own Redis repository is made by Spring Boot beside Contexa's distributed MFA store, and it keeps and finds a device")
    void theApplicationsRedisRepositoryIsMade() {
        withContexa(host(HostApplication.class, HostDevices.class)).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(RedisRepositoriesAutoConfiguration.class);

            String id = unique("device");
            remember(DEVICES, id);
            HostDeviceRepository repository = context.getBean(HostDeviceService.class).repository();
            repository.save(new HostDevice(id, "laptop"));

            assertThat(repository.findById(id)).map(HostDevice::getLabel).contains("laptop");
            assertThat(redis.hasKey(DEVICES + ":" + id)).as("the application's keyspace").isTrue();
        });
    }

    @Test
    @DisplayName("no bean of the application changes its name or its type, and what Contexa adds is no Spring Data Redis bean")
    void noBeanOfTheApplicationChanges() {
        AtomicReference<Map<String, String>> alone = new AtomicReference<>();
        host(HostApplication.class).run(context -> {
            assertThat(context).hasNotFailed();
            alone.set(beans(context));
        });
        withContexa(host(HostApplication.class)).run(context -> {
            assertThat(context).hasNotFailed();
            Map<String, String> withContexa = beans(context);

            Map<String, String> changed = new TreeMap<>();
            alone.get().forEach((name, type) -> {
                if (!type.equals(withContexa.get(name))) {
                    changed.put(name, type + " -> " + withContexa.get(name));
                }
            });
            Map<String, String> added = new TreeMap<>(withContexa);
            added.keySet().removeAll(alone.get().keySet());
            System.out.println("[beans] of the application changed or gone with Contexa: " + changed);
            System.out.println("[beans] added by Contexa: " + added);

            assertThat(changed).as("the application's beans, by name and type").isEmpty();
            assertThat(added.entrySet().stream().filter(bean -> bean.getValue().startsWith("org.springframework.data."))
                    .map(Map.Entry::getKey).toList())
                    .as("beans of Spring Data that Contexa puts in the application's context").isEmpty();
            assertThat(Arrays.asList(context.getBeanFactory().getBeanNamesForType(RedisRepositoryFactoryBean.class, true, false)))
                    .as("the Redis repositories of the context are the application's").containsExactly("&hostDeviceRepository");
            assertThat(Arrays.asList(context.getBeanFactory().getBeanNamesForType(RedisStateMachineRepository.class, true, false)))
                    .as("Contexa's store, under Contexa's name").containsExactly("contexaRedisStateMachineRepository");
            assertThat(((AbstractBeanDefinition) context.getBeanFactory().getBeanDefinition("contexaRedisStateMachineRepository"))
                    .isDefaultCandidate())
                    .as("an injection point of the application never gets Contexa's store by its type").isFalse();
            assertThat(context.getBeanFactory().getDependentBeans("contexaStringRedisTemplate"))
                    .as("Contexa's template outlives Contexa's store at shutdown").contains("contexaRedisStateMachineRepository");
            assertThat(context.getBeanFactory().getDependentBeans("redisTemplate"))
                    .as("the application's template is not Contexa's store's").doesNotContain("contexaRedisStateMachineRepository");
        });
    }

    @ParameterizedTest(name = "application name \"{0}\"")
    @ValueSource(strings = {"", APPLICATION})
    @DisplayName("Contexa keeps an MFA flow under the keys and in the form the repositories Spring Data enabled for the library kept it, and each reads what the other wrote")
    void theFlowsKeepTheirKeysAndForm(String applicationName) {
        String flow = unique("flow");
        String earlier = unique("earlier");
        String later = unique("later");
        Map<String, String> library = new TreeMap<>();
        Map<String, String> contexa = new TreeMap<>();
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(applicationName)) {
            String keyspace = ApplicationNamespace.key(FLOWS);
            for (String id : List.of(flow, earlier, later)) {
                keysToRemove.add(keyspace + ":" + id);
                remember(keyspace, id);
            }
            library().run(context -> {
                assertThat(context).hasNotFailed();
                StateMachinePersist<MfaState, MfaEvent, Object> persist = libraryPersist(context);
                persist.write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);
                library.putAll(stored(flow));
                redis.delete(keyspace + ":" + flow);
                persist.write(flowContext(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION), earlier);
            });
            withContexa(host(HostApplication.class)).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean("contexaMfaStateMachineService")).isInstanceOf(MfaStateMachineServiceImpl.class);
                StateMachinePersist<MfaState, MfaEvent, Object> persist = contexaPersist(context);
                persist.write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);
                contexa.putAll(stored(flow));

                assertThat(persist.read(flow).getState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
                StateMachineContext<MfaState, MfaEvent> kept = persist.read(earlier);
                assertThat(kept).as("a flow an earlier version kept").isNotNull();
                assertThat(kept.getState()).isEqualTo(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
                assertThat(kept.getExtendedState().getVariables()).containsEntry("factor", "OTT");
                persist.write(flowContext(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION), later);
            });
            library().run(context -> {
                StateMachineContext<MfaState, MfaEvent> kept = libraryPersist(context).read(later);
                assertThat(kept).as("the earlier version reads what this one kept").isNotNull();
                assertThat(kept.getState()).isEqualTo(MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION);
            });

            System.out.println("[keys] " + (applicationName.isEmpty() ? "without a name" : applicationName) + ": " + contexa);
            assertThat(contexa).as("the keys, their fields and their expiry").isEqualTo(library);
            assertThat(contexa).containsKeys(keyspace + ":" + flow, keyspace);
        }
    }

    @Test
    @DisplayName("an application without Redis repositories of its own keeps Contexa's flows, and its context holds no repository factory")
    void anApplicationWithoutRedisRepositories() {
        String flow = unique("flow");
        keysToRemove.add(FLOWS + ":" + flow);
        remember(FLOWS, flow);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            withContexa(host(HostApplicationWithoutRedisRepositories.class)).run(context -> {
                assertThat(context).hasNotFailed();
                StateMachinePersist<MfaState, MfaEvent, Object> persist = contexaPersist(context);
                persist.write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);

                assertThat(persist.read(flow).getState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
                assertThat(redis.hasKey(FLOWS + ":" + flow)).isTrue();
                assertThat(context.getBeanFactory().getBeanNamesForType(RedisRepositoryFactoryBean.class, true, false)).isEmpty();
            });
        }
    }

    @Test
    @DisplayName("an application that enables its Redis repositories itself keeps its keyspaces, and Contexa's flows stay behind the application's name")
    void anApplicationThatEnablesItsOwnRedisRepositories() {
        String id = unique("device");
        String flow = unique("flow");
        remember(DEVICES, id);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(APPLICATION)) {
            String keyspace = ApplicationNamespace.key(FLOWS);
            keysToRemove.add(keyspace + ":" + flow);
            keysToRemove.add(FLOWS + ":" + flow);
            remember(keyspace, flow);
            remember(FLOWS, flow);
            withContexa(host(HostApplicationEnablingItsRepositories.class, HostDevices.class)).run(context -> {
                assertThat(context).hasNotFailed();
                HostDeviceRepository repository = context.getBean(HostDeviceService.class).repository();
                repository.save(new HostDevice(id, "phone"));
                contexaPersist(context).write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);

                assertThat(redis.hasKey(DEVICES + ":" + id)).as("the application's keyspace").isTrue();
                assertThat(stored(flow).keySet()).as("Contexa's flow behind the application's name, and nowhere else")
                        .containsExactlyInAnyOrder(keyspace + ":" + flow, keyspace);
            });
        }
    }

    @Test
    @DisplayName("the flows go through Contexa's own template on the application's connection, not through an application template named redisTemplate on another database")
    void theFlowsUseContexasOwnTemplate() {
        String flow = unique("flow");
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            withContexa(host(HostApplicationWithItsOwnTemplate.class)).run(context -> {
                assertThat(context).hasNotFailed();
                contexaPersist(context).write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);

                StringRedisTemplate own = new StringRedisTemplate(HostApplicationWithItsOwnTemplate.connections);
                try {
                    assertThat(own.hasKey(FLOWS + ":" + flow)).as("not in the database of the application's template").isFalse();
                    assertThat(redis.hasKey(FLOWS + ":" + flow)).as("in the database of the application's connection").isTrue();
                    redis.delete(FLOWS + ":" + flow);
                    redis.opsForSet().remove(FLOWS, flow);
                } finally {
                    own.delete(FLOWS + ":" + flow);
                    own.opsForSet().remove(FLOWS, flow);
                }
            });
        }
    }

    @Test
    @DisplayName("an application with no template named redisTemplate, only a connection factory of its own, starts and keeps Contexa's flows on that connection")
    void anApplicationWithoutATemplateNamedRedisTemplate() {
        String flow = unique("flow");
        keysToRemove.add(FLOWS + ":" + flow);
        remember(FLOWS, flow);
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            withContexa(new ApplicationContextRunner().withUserConfiguration(HostApplicationWithOnlyAConnectionFactory.class))
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        assertThat(context).doesNotHaveBean("redisTemplate");
                        contexaPersist(context).write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);

                        assertThat(contexaPersist(context).read(flow).getState()).isEqualTo(MfaState.AWAITING_FACTOR_SELECTION);
                        assertThat(redis.hasKey(FLOWS + ":" + flow)).as("on the connection of the application").isTrue();
                    });
        }
    }

    @Test
    @DisplayName("a Redis that freezes holds a request for about a second once, and then not at all, however long the application's own client waits; it works again by itself")
    void aFrozenRedisDoesNotHoldRequestsForTheApplicationsWait() throws Exception {
        String flow = unique("flow");
        keysToRemove.add(FLOWS + ":" + flow);
        remember(FLOWS, flow);
        try (RedisOutageProxy proxy = new RedisOutageProxy(redisHost, redisPort);
             ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            host(HostApplicationWithoutRedisRepositories.class)
                    .withPropertyValues("spring.data.redis.port=" + proxy.port(), "spring.data.redis.timeout=10s")
                    .withUserConfiguration(ContexaSide.class)
                    .withPropertyValues("contexa.infrastructure.mode=distributed")
                    .withConfiguration(AutoConfigurations.of(CommonRedisAutoConfiguration.class, IdentityStateMachineAutoConfiguration.class))
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        StateMachinePersist<MfaState, MfaEvent, Object> persist = contexaPersist(context);
                        onRequestThread(() -> {
                            persist.write(flowContext(MfaState.AWAITING_FACTOR_SELECTION), flow);
                            return null;
                        });
                        assertThat(onRequestThread(() -> persist.read(flow))).as("read while Redis answers").isNotNull();

                        proxy.freeze();
                        Duration first = failureOnRequestThread(() -> persist.read(flow));
                        Duration second = failureOnRequestThread(() -> persist.read(flow));
                        assertThat(first).as("the request that meets the freeze").isLessThan(Duration.ofSeconds(4));
                        assertThat(second).as("a request while the gate is down").isLessThan(Duration.ofMillis(300));

                        proxy.restore();
                        await().atMost(Duration.ofSeconds(30)).ignoreExceptions().untilAsserted(() ->
                                assertThat(onRequestThread(() -> persist.read(flow))).as("read after Redis answers again").isNotNull());
                    });
        }
    }

    private static <T> T onRequestThread(Call<T> call) throws Exception {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        try {
            return call.run();
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }

    /** How long a call of a request thread takes to fail. */
    private static Duration failureOnRequestThread(Call<?> call) throws Exception {
        long start = System.nanoTime();
        try {
            onRequestThread(call);
        } catch (RuntimeException failure) {
            return Duration.ofNanos(System.nanoTime() - start);
        }
        throw new AssertionError("the call was expected to fail");
    }

    @FunctionalInterface
    private interface Call<T> {
        T run() throws Exception;
    }

    private static ApplicationContextRunner host(Class<?>... configurations) {
        return new ApplicationContextRunner()
                .withPropertyValues("spring.data.redis.host=" + redisHost, "spring.data.redis.port=" + redisPort)
                .withUserConfiguration(configurations)
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, RedisRepositoriesAutoConfiguration.class));
    }

    private static ApplicationContextRunner withContexa(ApplicationContextRunner host) {
        return host.withPropertyValues("contexa.infrastructure.mode=distributed")
                .withUserConfiguration(ContexaSide.class)
                .withConfiguration(AutoConfigurations.of(CommonRedisAutoConfiguration.class, IdentityStateMachineAutoConfiguration.class));
    }

    /** The repositories the distributed mode used to enable: Spring Data's, on the package of Spring Statemachine. */
    private static ApplicationContextRunner library() {
        return new ApplicationContextRunner()
                .withPropertyValues("spring.data.redis.host=" + redisHost, "spring.data.redis.port=" + redisPort)
                .withUserConfiguration(LibraryRepositories.class)
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class));
    }

    private static StateMachinePersist<MfaState, MfaEvent, Object> libraryPersist(ConfigurableApplicationContext context) {
        return new ExpiringRedisRepositoryStateMachinePersist(context.getBean(RedisStateMachineRepository.class),
                new MfaKryoStateMachineSerialisationService(), TTL);
    }

    @SuppressWarnings("unchecked")
    private static StateMachinePersist<MfaState, MfaEvent, Object> contexaPersist(ConfigurableApplicationContext context) {
        return context.getBean("contexaStateMachinePersist", StateMachinePersist.class);
    }

    private static StateMachineContext<MfaState, MfaEvent> flowContext(MfaState state) {
        DefaultExtendedState extendedState = new DefaultExtendedState();
        extendedState.getVariables().put("factor", "OTT");
        return new DefaultStateMachineContext<>(state, null, null, extendedState, null, "mfa");
    }

    /** What Redis holds for a flow: each key with its type, its fields and whether it expires, and the sets that name it. */
    private static Map<String, String> stored(String id) {
        Map<String, String> stored = new TreeMap<>();
        for (String key : redis.keys("*" + id + "*")) {
            Map<byte[], byte[]> fields = redis.execute((RedisCallback<Map<byte[], byte[]>>) connection ->
                    connection.hashCommands().hGetAll(key.getBytes(StandardCharsets.UTF_8)));
            Long seconds = redis.getExpire(key);
            boolean expires = seconds != null && seconds > TTL.toSeconds() - 60 && seconds <= TTL.toSeconds();
            stored.put(key, redis.type(key).code() + " expires=" + expires + " " + fields.entrySet().stream()
                    .map(field -> new String(field.getKey(), StandardCharsets.UTF_8) + "="
                            + Base64.getEncoder().encodeToString(field.getValue()))
                    .sorted().collect(Collectors.joining(", ", "{", "}")));
        }
        for (String set : List.of(FLOWS, ApplicationNamespace.key(FLOWS))) {
            if (Boolean.TRUE.equals(redis.opsForSet().isMember(set, id))) {
                stored.put(set, "set holding the flow");
            }
        }
        return stored;
    }

    /** The beans of a context by name, with the type each is of. */
    private static Map<String, String> beans(ConfigurableApplicationContext context) {
        ConfigurableListableBeanFactory factory = context.getBeanFactory();
        Map<String, String> beans = new TreeMap<>();
        for (String name : factory.getBeanDefinitionNames()) {
            Class<?> type = factory.getType(name, false);
            beans.put(name, type == null ? "unknown" : Proxy.isProxyClass(type)
                    ? Arrays.stream(type.getInterfaces()).map(Class::getName).collect(Collectors.joining("&", "proxy:", ""))
                    : type.getName());
        }
        return beans;
    }

    private void remember(String set, String member) {
        membersToRemove.computeIfAbsent(set, ignored -> new ArrayList<>()).add(member);
        keysToRemove.add(set.equals(DEVICES) ? DEVICES + ":" + member : set + ":" + member);
    }

    private static String unique(String what) {
        return "host-redis-" + what + "-" + UUID.randomUUID();
    }

    /** The application: Spring Boot looks for its repositories in its package. */
    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage(basePackageClasses = HostDeviceRepository.class)
    static class HostApplication {
    }

    /**
     * An application whose template named redisTemplate is its own, on database 3 of the Redis, and kept from the
     * injection points: Spring Boot makes no template of that name beside it.
     */
    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage(basePackageClasses = HostDeviceRepository.class)
    static class HostApplicationWithItsOwnTemplate {

        static LettuceConnectionFactory connections;

        @Bean(autowireCandidate = false)
        RedisTemplate<Object, Object> redisTemplate() {
            RedisStandaloneConfiguration databaseThree = new RedisStandaloneConfiguration(redisHost, redisPort);
            databaseThree.setDatabase(3);
            connections = new LettuceConnectionFactory(databaseThree);
            connections.afterPropertiesSet();
            RedisTemplate<Object, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(connections);
            template.afterPropertiesSet();
            return template;
        }
    }

    /** An application with a connection factory of its own and no template of any name: Spring Boot's Redis auto-configuration is not used. */
    @Configuration(proxyBeanMethods = false)
    static class HostApplicationWithOnlyAConnectionFactory {

        @Bean
        LettuceConnectionFactory hostConnections() {
            return new LettuceConnectionFactory(new RedisStandaloneConfiguration(redisHost, redisPort));
        }
    }

    /** An application whose package has no Redis repository. */
    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage(basePackages = "io.contexa.autoconfigure.hostredis.none")
    static class HostApplicationWithoutRedisRepositories {
    }

    /** An application that enables its Redis repositories itself, with Spring Data's default keyspaces. */
    @Configuration(proxyBeanMethods = false)
    @EnableRedisRepositories(basePackageClasses = HostDeviceRepository.class)
    static class HostApplicationEnablingItsRepositories {
    }

    /** The application's code that takes its repository: without the repository the application does not start. */
    @Configuration(proxyBeanMethods = false)
    static class HostDevices {

        @Bean
        HostDeviceService hostDeviceService(HostDeviceRepository repository) {
            return new HostDeviceService(repository);
        }
    }

    record HostDeviceService(HostDeviceRepository repository) {
    }

    /** What the distributed MFA store stands on in an application of Contexa: the platform, its policies, and Redisson. */
    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {

        @Bean
        PlatformConfig platformConfig() {
            return PlatformConfig.builder().build();
        }

        @Bean
        MfaPolicyProvider mfaPolicyProvider() {
            return mock(MfaPolicyProvider.class);
        }

        @Bean
        AuthContextProperties authContextProperties() {
            return new AuthContextProperties();
        }

        @Bean
        MfaSessionRepository contexaMfaSessionRepository() {
            return mock(MfaSessionRepository.class);
        }

        @Bean(destroyMethod = "shutdown")
        RedissonClient contexaRedissonClient() {
            Config config = new Config();
            config.useSingleServer().setAddress("redis://" + redisHost + ":" + redisPort);
            return Redisson.create(config);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableRedisRepositories(basePackages = "org.springframework.statemachine.data.redis",
            keyspaceConfiguration = ApplicationStateMachineKeyspaces.class)
    static class LibraryRepositories {
    }
}
