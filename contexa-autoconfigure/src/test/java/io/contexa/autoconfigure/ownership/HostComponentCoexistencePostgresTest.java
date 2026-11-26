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
package io.contexa.autoconfigure.ownership;

import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.autoconfigure.hostapp.HostOrderRepository;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaiam.repository.ManagedResourceRepositoryCustomImpl;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import net.javacrumbs.shedlock.core.LockProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.DependencyDescriptor;
import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.orm.jpa.EntityManagerFactoryUtils;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M0 of the operating-mode plan (docs/agent/운영모드-정상화-구현계획.md, R-6): an application that has components of the same
 * types Contexa has keeps its own wherever it asks for them by type, and Contexa keeps its own wherever it asks for them,
 * by name, in every way of running Contexa. Neither side's components reach the other's.
 * <p>
 * One application, started in each of the four combinations on a real port over a throwaway PostgreSQL database of
 * Contexa's and an in-memory database of its own, with its own users, provider, permission evaluator, query factory, lock
 * provider, client registrations, JPA and Redis; once with a security chain and a form sign-in of its own, once without a
 * chain (where there is no sign-in of its own to observe). Every lookup of the
 * application is resolved as Spring resolves an injection point of its code (a required field, by type, through
 * {@link DependencyDescriptor}), one at a time, so that one conflict does not hide the others; at an injection point of a
 * constructor the same conflict would stop the application's start. The application's sign-in and its session are
 * observed over HTTP. Contexa's side is read from Contexa's components as they run.
 */
@Timeout(3600)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@DisplayName("호스트 구성요소와 Contexa 구성요소 공존 계약(실제 기동)")
class HostComponentCoexistencePostgresTest {

    @BeforeAll
    static void driver() throws Exception {
        Class.forName("org.postgresql.Driver");
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(OperatingCombination.class)
    @DisplayName("호스트의 타입 주입은 호스트 것을, Contexa 내부는 이름으로 Contexa 것을 받는다")
    void eachSideKeepsItsOwnComponents(OperatingCombination combination) throws Exception {
        try (GridRun run = GridRun.start(SandboxWithItsComponents.class, FullWithItsComponents.class, combination, redis())) {
            Map<String, String> observed = coexistence(run, true, combination);
            System.out.println("COEXISTENCE [with its chain, " + combination + "] " + observed);

            assertThat(observed).isEqualTo(expected(true, combination));
        }
    }

    /**
     * The same components in an application that has no security chain of its own: its lookups and Contexa's are the same
     * contract, and its sign-in is not there to observe.
     */
    @ParameterizedTest(name = "{0}")
    @EnumSource(OperatingCombination.class)
    @DisplayName("보안 체인이 없는 호스트도 타입 주입은 호스트 것을, Contexa 내부는 이름으로 Contexa 것을 받는다")
    void eachSideKeepsItsOwnComponentsWithoutAChainOfTheApplication(OperatingCombination combination) throws Exception {
        try (GridRun run = GridRun.start(SandboxWithItsComponentsButNoChain.class, FullWithItsComponentsButNoChain.class,
                combination, redis())) {
            Map<String, String> observed = coexistence(run, false, combination);
            System.out.println("COEXISTENCE [without its chain, " + combination + "] " + observed);

            assertThat(observed).isEqualTo(expected(false, combination));
        }
    }

    /**
     * The host's Redis: the isolated one the tests are given, never a default address. Without
     * {@code CONTEXA_TEST_REDIS_PORT} the test is skipped before it creates its database.
     */
    private static String[] redis() {
        TestStores.Redis redis = TestStores.redis();
        return new String[] {"spring.data.redis.host=" + redis.host(), "spring.data.redis.port=" + redis.port()};
    }

    private static Map<String, String> expected(boolean hostSignsIn, OperatingCombination combination) {
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("start", GridRun.STARTED);
        expected.put("the application's UserDetailsService", "hostUsers");
        expected.put("the application's AuthenticationProvider", "hostProvider");
        expected.put("the application's PermissionEvaluator", "hostPermissionEvaluator");
        expected.put("the application's JPAQueryFactory", "hostQueryFactory");
        expected.put("the application's LockProvider", "hostLockProvider");
        expected.put("the application's ClientRegistrationRepository", "hostClientRegistrations");
        expected.put("the application's EntityManager", "of entityManagerFactory");
        expected.put("the application's default persistence unit", "entityManagerFactory");
        expected.put("the application's StringRedisTemplate", "stringRedisTemplate");
        expected.put("the application's RedisTemplate<Object, Object>", "redisTemplate");
        expected.put("the application's repository on its own database", "0");
        if (hostSignsIn) {
            expected.put("the application's sign-in of its user", "302 /");
            expected.put("the application's sign-in of Contexa's administrator", "302 " + GridRun.hostLoginPath(combination) + "?error");
            expected.put("the application's page after its sign-in", "200 host data");
            expected.put("what Contexa keeps in the application's session", "[]");
        }
        expected.put("Contexa's user store, by its name", "present");
        expected.put("the store Contexa's sign-in reads", ContexaUserStore.BEAN_NAME);
        expected.put("Contexa's password provider, by its name", "present");
        expected.put("Contexa's permission evaluator, by its name", "present");
        expected.put("Contexa's query factory, by its name", "present");
        expected.put("the query factory Contexa's resource repository queries with", "contexaJpaQueryFactory");
        expected.put("Contexa's lock provider, by its name", "present");
        expected.put("Contexa's user repository reads Contexa's database", "true");
        // Contexa's OAuth2 plane, its client registrations among it, is there in mode FULL only (R-11)
        expected.put("Contexa's client registrations, by its name",
                combination.mode() == SecurityMode.FULL ? "present" : "absent");
        return expected;
    }

    private static Map<String, String> coexistence(GridRun run, boolean hostSignsIn, OperatingCombination combination) {
        Map<String, String> observed = new LinkedHashMap<>();
        observed.put("start", run.startOutcome());
        if (!run.started()) {
            return observed;
        }
        ConfigurableApplicationContext context = run.context();
        observed.put("the application's UserDetailsService", GridRun.attempt(() -> injected(context, "userDetailsService")));
        observed.put("the application's AuthenticationProvider", GridRun.attempt(() -> injected(context, "authenticationProvider")));
        observed.put("the application's PermissionEvaluator", GridRun.attempt(() -> injected(context, "permissionEvaluator")));
        observed.put("the application's JPAQueryFactory", GridRun.attempt(() -> injected(context, "queryFactory")));
        observed.put("the application's LockProvider", GridRun.attempt(() -> injected(context, "lockProvider")));
        observed.put("the application's ClientRegistrationRepository", GridRun.attempt(() -> injected(context, "clientRegistrationRepository")));
        observed.put("the application's EntityManager", GridRun.attempt(() -> {
            Object resolved = resolve(context, "entityManager");
            if (!(resolved instanceof EntityManager entityManager)) {
                return String.valueOf(resolved);
            }
            return "of " + nameOf(context, EntityManagerFactory.class, entityManager.getEntityManagerFactory());
        }));
        observed.put("the application's default persistence unit", GridRun.attempt(() -> nameOf(context, EntityManagerFactory.class,
                EntityManagerFactoryUtils.findEntityManagerFactory(context.getBeanFactory(), null))));
        observed.put("the application's StringRedisTemplate", GridRun.attempt(() -> injected(context, "stringRedisTemplate")));
        observed.put("the application's RedisTemplate<Object, Object>", GridRun.attempt(() -> injected(context, "redisTemplate")));
        observed.put("the application's repository on its own database", GridRun.attempt(() ->
                String.valueOf(context.getBean(HostOrderRepository.class).count())));

        if (hostSignsIn) {
            GridRun.Browser user = run.browser();
            observed.put("the application's sign-in of its user", GridRun.attempt(() ->
                    run.hostSignIn(user, GridRun.HOST_USER, GridRun.HOST_PASSWORD, GridRun.hostLoginPath(combination))));
            observed.put("the application's sign-in of Contexa's administrator", GridRun.attempt(() ->
                    run.hostSignIn(run.browser(), GridRun.ADMIN, GridRun.ADMIN_PASSWORD, GridRun.hostLoginPath(combination))));
            observed.put("the application's page after its sign-in", GridRun.attempt(() -> {
                var page = user.get(GridController.SECURED, "application/json");
                return page.statusCode() + " " + page.body();
            }));
            observed.put("what Contexa keeps in the application's session", GridRun.attempt(() -> {
                user.get(GridController.OPEN, "application/json");
                String names = user.get(GridController.SESSION_ATTRIBUTES, "application/json").body();
                return Arrays.toString(Arrays.stream(names.replaceAll("[\\[\\]\"]", "").split(","))
                        .map(String::trim)
                        .filter(name -> !name.isEmpty() && !name.startsWith("SPRING_SECURITY_")
                                && !name.startsWith("org.springframework.security."))
                        .toArray());
            }));
        }

        observed.put("Contexa's user store, by its name", GridRun.attempt(() -> present(context.containsBean(ContexaUserStore.BEAN_NAME))));
        // Contexa's store is held where it is not offered by type (R-17), so it is told by being Contexa's own, not by a lookup
        observed.put("the store Contexa's sign-in reads", GridRun.attempt(() -> {
            UserDetailsService signIn = ContexaUserStore.forSignIn(context.getBeanFactory());
            return signIn == ContexaUserStore.own(context.getBeanFactory()) ? ContexaUserStore.BEAN_NAME
                    : nameOf(context, UserDetailsService.class, signIn);
        }));
        observed.put("Contexa's password provider, by its name", GridRun.attempt(() ->
                present(context.containsBean("contexaCustomAuthenticationProvider"))));
        observed.put("Contexa's permission evaluator, by its name", GridRun.attempt(() ->
                present(context.containsBean("contexaCompositePermissionEvaluator"))));
        observed.put("Contexa's query factory, by its name", GridRun.attempt(() -> present(context.containsBean("contexaJpaQueryFactory"))));
        observed.put("the query factory Contexa's resource repository queries with", GridRun.attempt(() -> {
            ManagedResourceRepositoryCustomImpl repository = context.getBeanProvider(ManagedResourceRepositoryCustomImpl.class).getIfAvailable();
            return repository == null ? "no repository"
                    : nameOf(context, JPAQueryFactory.class, ReflectionTestUtils.getField(repository, "queryFactory"));
        }));
        observed.put("Contexa's lock provider, by its name", GridRun.attempt(() -> present(context.containsBean("contexaShedLockProvider"))));
        observed.put("Contexa's user repository reads Contexa's database", GridRun.attempt(() -> {
            long repository = context.getBean("contexaUserRepository", UserRepository.class).count();
            Long table = run.contexaDatabase().queryForObject("select count(*) from ctxa_users", Long.class);
            return String.valueOf(table != null && table > 0 && repository == table);
        }));
        observed.put("Contexa's client registrations, by its name", GridRun.attempt(() ->
                present(context.containsBean("contexaClientRegistrationRepository"))));
        return observed;
    }

    /** The bean an injection point of the application's code gets: its name, or why there is none. */
    private static String injected(ConfigurableApplicationContext context, String field) throws Exception {
        Object resolved = resolve(context, field);
        if (resolved instanceof String answer) {
            return answer;
        }
        Field declared = ApplicationInjectionPoints.class.getDeclaredField(field);
        return nameOf(context, declared.getType(), resolved);
    }

    /** Resolves a field of {@link ApplicationInjectionPoints} as Spring resolves a required field of the application. */
    private static Object resolve(ConfigurableApplicationContext context, String field) throws Exception {
        DependencyDescriptor descriptor = new DependencyDescriptor(ApplicationInjectionPoints.class.getDeclaredField(field), true);
        try {
            return context.getAutowireCapableBeanFactory().resolveDependency(descriptor, "applicationInjectionPoints");
        } catch (NoUniqueBeanDefinitionException ambiguous) {
            return "ambiguous: " + ambiguous.getBeanNamesFound();
        } catch (NoSuchBeanDefinitionException none) {
            return "none";
        }
    }

    private static String nameOf(ConfigurableApplicationContext context, Class<?> type, Object bean) {
        if (bean == null) {
            return "null";
        }
        for (String name : context.getBeanFactory().getBeanNamesForType(type, true, false)) {
            if (context.getBean(name) == bean) {
                return name;
            }
        }
        return "an unnamed " + bean.getClass().getSimpleName();
    }

    private static String present(boolean present) {
        return present ? "present" : "absent";
    }

    /** The injection points of the application's code, named as an application names them. */
    @SuppressWarnings("unused")
    static final class ApplicationInjectionPoints {
        UserDetailsService userDetailsService;
        AuthenticationProvider authenticationProvider;
        PermissionEvaluator permissionEvaluator;
        JPAQueryFactory queryFactory;
        LockProvider lockProvider;
        ClientRegistrationRepository clientRegistrationRepository;
        EntityManager entityManager;
        StringRedisTemplate stringRedisTemplate;
        RedisTemplate<Object, Object> redisTemplate;
    }

    // ----- the application, once per mode -----

    /**
     * An application with a component of each type Contexa also has. None of its beans takes another of these types by
     * type: each lookup is made by the test, one at a time.
     */
    abstract static class ApplicationComponents extends GridModels {

        @Bean
        UserDetailsService hostUsers() {
            return users();
        }

        @Bean
        AuthenticationProvider hostProvider() {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users());
            provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
            return provider;
        }

        @Bean
        PermissionEvaluator hostPermissionEvaluator() {
            return new PermissionEvaluator() {
                @Override
                public boolean hasPermission(Authentication authentication, Object target, Object permission) {
                    return true;
                }

                @Override
                public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
                    return true;
                }
            };
        }

        @Bean
        JPAQueryFactory hostQueryFactory(@Qualifier("entityManagerFactory") EntityManagerFactory entityManagerFactory) {
            return new JPAQueryFactory(SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory));
        }

        @Bean
        LockProvider hostLockProvider() {
            return configuration -> Optional.empty();
        }

        @Bean
        ClientRegistrationRepository hostClientRegistrations() {
            return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("host-idp")
                    .clientId("host-client")
                    .clientSecret("host-client-secret")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .tokenUri("http://127.0.0.1:1/token")
                    .build());
        }

        private static InMemoryUserDetailsManager users() {
            return new InMemoryUserDetailsManager(User.withUsername(GridRun.HOST_USER)
                    .password("{noop}" + GridRun.HOST_PASSWORD).roles("USER").build());
        }
    }

    /**
     * An existing Spring Security application: those components and a chain of its own with its form sign-in, narrowed to
     * its own paths with mode FULL ({@link GridRun#hostChain}, R-14).
     */
    abstract static class ApplicationWithItsComponents extends ApplicationComponents {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return GridRun.hostChain(http, narrowed());
        }

        boolean narrowed() {
            return false;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @AutoConfigurationPackage(basePackageClasses = HostOrderRepository.class)
    @EnableAISecurity
    static class SandboxWithItsComponents extends ApplicationWithItsComponents {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @AutoConfigurationPackage(basePackageClasses = HostOrderRepository.class)
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithItsComponents extends ApplicationWithItsComponents {

        @Override
        boolean narrowed() {
            return true;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @AutoConfigurationPackage(basePackageClasses = HostOrderRepository.class)
    @EnableAISecurity
    static class SandboxWithItsComponentsButNoChain extends ApplicationComponents {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @AutoConfigurationPackage(basePackageClasses = HostOrderRepository.class)
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithItsComponentsButNoChain extends ApplicationComponents {
    }
}
