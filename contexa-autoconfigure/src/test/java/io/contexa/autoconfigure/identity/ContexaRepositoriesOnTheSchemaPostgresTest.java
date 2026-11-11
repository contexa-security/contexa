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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacommon.entity.behavior.UserBehaviorProfile;
import io.contexa.contexacommon.repository.UserBehaviorProfileRepository;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexaiam.domain.entity.PolicyTemplate;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import jakarta.persistence.EntityManagerFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.core.RepositoryMetadata;
import org.springframework.data.repository.core.support.AbstractRepositoryMetadata;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Every JPA entity of Contexa meets the schema it is installed with, on a real PostgreSQL: on a database installed from
 * the canonical schema and on one that was installed before the ctxa_ prefix and brought to the current schema by the
 * start's own steps (the move of the names, then the idempotent maintenance). Hibernate's validation of the schema must
 * pass, every method of every repository must run without a SQL error that names the schema or the statement (a column,
 * a table, a type or a function the database does not know) and without a null where a primitive is promised, and what
 * the entities that carry a version or a JSON column write can be read back.
 */
class ContexaRepositoriesOnTheSchemaPostgresTest {

    private static final String SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String SCHEMA_BEFORE_THE_PREFIX = "db/schema-before-ctxa-prefix.sql";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static PostgresTestDatabase installed;
    private static PostgresTestDatabase upgraded;

    @BeforeAll
    static void installTheTwoDatabases() throws Exception {
        installed = PostgresTestDatabase.empty();
        run(installed, SCHEMA);
        seed(installed);

        upgraded = PostgresTestDatabase.empty();
        run(upgraded, SCHEMA_BEFORE_THE_PREFIX);
        // a row the old outbox table already holds, written before the entity carried a version
        upgraded.jdbcTemplate().update("insert into security_decision_forwarding_outbox (attempt_count, correlation_id, "
                + "created_at, payload_json, status, tenant_external_ref, updated_at) "
                + "values (0, 'before-the-upgrade', now(), '{}', 'PENDING', 'tenant-old', now())");
        assertThat(new ContexaSchemaPrefixMigration(upgraded.dataSource()).migrate())
                .isEqualTo(ContexaSchemaPrefixMigration.Outcome.MIGRATED);
        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(
                upgraded.dataSource(), new OssSchemaMaintenanceBacklog(upgraded.dataSource()), false);
        seed(upgraded);
    }

    @AfterAll
    static void drop() {
        if (installed != null) {
            installed.close();
        }
        if (upgraded != null) {
            upgraded.close();
        }
    }

    @Test
    @DisplayName("Hibernate's schema validation accepts the entities on an installed database")
    void validationAcceptsAnInstalledDatabase() {
        withJpa(installed, context -> assertThat(context).hasNotFailed(), "contexa.jpa.hibernate.ddl-auto=validate");
    }

    @Test
    @DisplayName("Hibernate's schema validation accepts the entities on a database upgraded in place")
    void validationAcceptsAnUpgradedDatabase() {
        withJpa(upgraded, context -> assertThat(context).hasNotFailed(), "contexa.jpa.hibernate.ddl-auto=validate");
    }

    @Test
    @DisplayName("No repository method fails on the schema of an installed database")
    void noRepositoryMethodFailsOnAnInstalledDatabase() {
        withJpa(installed, context -> assertThat(schemaFailures(context)).isEmpty());
    }

    @Test
    @DisplayName("No repository method fails on the schema of a database upgraded in place")
    void noRepositoryMethodFailsOnAnUpgradedDatabase() {
        withJpa(upgraded, context -> assertThat(schemaFailures(context)).isEmpty());
    }

    @Test
    @DisplayName("The forwarding outbox is claimed, updated and guarded by its version on an installed database")
    void theOutboxKeepsItsVersionOnAnInstalledDatabase() {
        withJpa(installed, ContexaRepositoriesOnTheSchemaPostgresTest::theOutboxKeepsItsVersion);
    }

    @Test
    @DisplayName("The forwarding outbox is claimed, updated and guarded by its version on a database upgraded in place")
    void theOutboxKeepsItsVersionOnAnUpgradedDatabase() {
        withJpa(upgraded, context -> {
            theOutboxKeepsItsVersion(context);
            // the row the old table held takes the version 0 and is claimed like any other
            SecurityDecisionForwardingOutboxRepository outbox =
                    context.getBean(SecurityDecisionForwardingOutboxRepository.class);
            SecurityDecisionForwardingOutboxRecord old = outbox.findByCorrelationId("before-the-upgrade").orElseThrow();
            assertThat(old.getVersion()).isZero();
            assertThat(outbox.claimForDispatch(old.getId(), List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING),
                    SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING, LocalDateTime.now())).isEqualTo(1);
            assertThat(outbox.findById(old.getId()).orElseThrow().getVersion()).isEqualTo(1L);
        });
    }

    @Test
    @DisplayName("A row written without a version by SQL reads with the version 0")
    void aRowWrittenBySqlHasTheVersionZero() {
        installed.jdbcTemplate().update("insert into ctxa_security_decision_forwarding_outbox (attempt_count, "
                + "correlation_id, created_at, payload_json, status, tenant_external_ref, updated_at) "
                + "values (0, 'by-sql', now(), '{}', 'PENDING', 'tenant-sql', now())");
        withJpa(installed, context -> assertThat(context.getBean(SecurityDecisionForwardingOutboxRepository.class)
                .findByCorrelationId("by-sql").orElseThrow().getVersion()).isZero());
    }

    @Test
    @DisplayName("A behavior profile with JSON columns is stored and read back, on both databases")
    void aBehaviorProfileWithJsonIsStoredAndReadBack() {
        for (PostgresTestDatabase database : List.of(installed, upgraded)) {
            withJpa(database, context -> {
                UserBehaviorProfileRepository profiles = context.getBean(UserBehaviorProfileRepository.class);
                String user = "profile-" + UUID.randomUUID();
                UserBehaviorProfile profile = new UserBehaviorProfile();
                profile.setUserId(user);
                profile.setProfileType("WORKDAY");
                profile.setNormalRangeMetadata("{\"hours\": [9, 17]}");
                profile.setCommonActivities("[\"login\", \"view\"]");
                profile.setCommonIpRanges("[\"10.0.0.0/8\"]");
                profiles.save(profile);

                UserBehaviorProfile read = profiles.findByUserId(user).get(0);
                assertThat(json(read.getNormalRangeMetadata())).isEqualTo(json("{\"hours\": [9, 17]}"));
                assertThat(json(read.getCommonActivities())).isEqualTo(json("[\"login\", \"view\"]"));
                assertThat(json(read.getCommonIpRanges())).isEqualTo(json("[\"10.0.0.0/8\"]"));

                String bare = "bare-" + UUID.randomUUID();
                UserBehaviorProfile withoutJson = new UserBehaviorProfile();
                withoutJson.setUserId(bare);
                withoutJson.setProfileType("WORKDAY");
                profiles.save(withoutJson);
                UserBehaviorProfile readBare = profiles.findByUserId(bare).get(0);
                assertThat(readBare.getNormalRangeMetadata()).isNull();
                assertThat(readBare.getCommonActivities()).isNull();
                assertThat(readBare.getCommonIpRanges()).isNull();

                assertThat(database.jdbcTemplate().queryForObject("select pg_typeof(common_activities)::text "
                        + "from ctxa_user_behavior_profiles where user_id = ?", String.class, user))
                        .as("the column keeps its type").isEqualTo("json");
            });
        }
    }

    @Test
    @DisplayName("A policy template with its draft is stored and read back, on both databases")
    void aPolicyTemplateWithItsDraftIsStoredAndReadBack() {
        for (PostgresTestDatabase database : List.of(installed, upgraded)) {
            withJpa(database, context -> {
                PolicyTemplateRepository templates = context.getBean(PolicyTemplateRepository.class);
                String templateId = "template-" + UUID.randomUUID();
                templates.save(template(templateId, "{\"name\": \"read-only\", \"rules\": []}"));

                PolicyTemplate read = templates.findAll().stream()
                        .filter(candidate -> templateId.equals(candidate.getTemplateId())).findFirst().orElseThrow();
                assertThat(json(read.getPolicyDraftJson())).isEqualTo(json("{\"name\": \"read-only\", \"rules\": []}"));
                assertThat(database.jdbcTemplate().queryForObject("select pg_typeof(policy_draft_json)::text "
                        + "from ctxa_policy_template where template_id = ?", String.class, templateId))
                        .as("the column keeps its type").isEqualTo("jsonb");
            });
        }
    }

    private static void theOutboxKeepsItsVersion(AssertableApplicationContext context) {
        SecurityDecisionForwardingOutboxRepository outbox =
                context.getBean(SecurityDecisionForwardingOutboxRepository.class);
        String correlation = "outbox-" + UUID.randomUUID();
        SecurityDecisionForwardingOutboxRecord saved = outbox.save(SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId(correlation).tenantExternalRef("tenant-a").payloadJson("{\"k\": 1}").build());
        Long id = saved.getId();
        assertThat(saved.getVersion()).isZero();
        LocalDateTime now = LocalDateTime.now();
        assertThat(outbox.findDispatchableIds(List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING), now,
                PageRequest.of(0, 1000))).contains(id);

        assertThat(outbox.claimForDispatch(id, List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING),
                SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING, now)).isEqualTo(1);
        SecurityDecisionForwardingOutboxRecord claimed = outbox.findByCorrelationId(correlation).orElseThrow();
        assertThat(claimed.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING);
        assertThat(claimed.getAttemptCount()).isEqualTo(1);
        assertThat(claimed.getVersion()).isEqualTo(1L);
        assertThat(outbox.claimForDispatch(id, List.of(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING),
                SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING, now))
                .as("a claimed record is not claimed twice").isZero();

        SecurityDecisionForwardingOutboxRecord first = outbox.findById(id).orElseThrow();
        SecurityDecisionForwardingOutboxRecord second = outbox.findById(id).orElseThrow();
        first.markDelivered(now);
        assertThat(outbox.save(first).getVersion()).isEqualTo(2L);
        second.markRetry("late", now.plusMinutes(1));
        assertThatThrownBy(() -> outbox.save(second))
                .as("an update from a copy read before the first update is refused")
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);
        assertThat(outbox.findById(id).orElseThrow().getStatus())
                .isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_DELIVERED);
    }

    /** The calls that failed on the schema or on the statement itself: the call and what the database said. */
    private static Map<String, String> schemaFailures(AssertableApplicationContext context) {
        assertThat(context).hasNotFailed();
        EntityManagerFactory entityManagerFactory =
                context.getBean("contexaEntityManagerFactory", EntityManagerFactory.class);
        TransactionTemplate transaction = new TransactionTemplate(
                context.getBean("contexaTransactionManager", PlatformTransactionManager.class));
        Set<Class<?>> entityTypes = entityManagerFactory.getMetamodel().getEntities().stream()
                .map(entity -> (Class<?>) entity.getJavaType()).collect(Collectors.toSet());
        Map<String, Object> repositories = new TreeMap<>();
        Map<String, Class<?>> repositoryTypes = new TreeMap<>();
        for (Object bean : context.getBeansOfType(Repository.class).values()) {
            for (Class<?> type : AopProxyUtils.proxiedUserInterfaces(bean)) {
                if (Repository.class.isAssignableFrom(type) && type.getName().startsWith("io.contexa.")) {
                    repositories.put(type.getName(), bean);
                    repositoryTypes.put(type.getName(), type);
                }
            }
        }
        assertThat(repositories).as("the repositories of Contexa").hasSizeGreaterThanOrEqualTo(56);

        Map<String, String> failures = new TreeMap<>();
        int calls = 0;
        for (Map.Entry<String, Object> repository : repositories.entrySet()) {
            Class<?> type = repositoryTypes.get(repository.getKey());
            RepositoryMetadata metadata = AbstractRepositoryMetadata.getMetadata(type);
            for (Method method : ContexaJpaMinimumDialectPostgresTest.exercisedMethods(type)) {
                Object[] arguments = ContexaJpaMinimumDialectPostgresTest.arguments(method, metadata, entityTypes);
                String call = type.getSimpleName() + "#" + method.getName();
                calls++;
                try {
                    transaction.executeWithoutResult(status -> {
                        status.setRollbackOnly();
                        try {
                            method.invoke(repository.getValue(), arguments);
                        } catch (InvocationTargetException failure) {
                            throw new CallFailure(failure.getTargetException());
                        } catch (IllegalAccessException impossible) {
                            throw new IllegalStateException(impossible);
                        }
                    });
                } catch (RuntimeException failure) {
                    String schema = schemaFailure(failure instanceof CallFailure ? failure.getCause() : failure);
                    if (schema != null) {
                        failures.merge(call, schema, (before, after) -> before + " | " + after);
                    }
                }
            }
        }
        assertThat(calls).as("the repository calls made").isGreaterThan(400);
        System.out.println("[repositories on the schema] " + calls + " calls, " + failures.size() + " failed on the schema");
        failures.forEach((call, failure) -> System.out.println("[repositories on the schema]   " + call + " -> " + failure));
        return failures;
    }

    /** What the database said when it is about the schema or the statement; null when the call failed for another reason. */
    private static String schemaFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause() == cause ? null : cause.getCause()) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null && sql.getSQLState().startsWith("42")) {
                return "SQLState " + sql.getSQLState() + ": " + firstLine(sql.getMessage());
            }
            if (cause.getClass().getSimpleName().equals("AopInvocationException")) {
                return "AopInvocationException: " + firstLine(cause.getMessage());
            }
        }
        return null;
    }

    private static String firstLine(String message) {
        return message == null ? "" : message.lines().findFirst().orElse("");
    }

    private static final class CallFailure extends RuntimeException {

        CallFailure(Throwable cause) {
            super(cause);
        }
    }

    private static PolicyTemplate template(String templateId, String draft) {
        try {
            Constructor<PolicyTemplate> constructor = PolicyTemplate.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            PolicyTemplate template = constructor.newInstance();
            ReflectionTestUtils.setField(template, "templateId", templateId);
            ReflectionTestUtils.setField(template, "name", "Template " + templateId);
            ReflectionTestUtils.setField(template, "policyDraftJson", draft);
            return template;
        } catch (ReflectiveOperationException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static JsonNode json(String text) {
        try {
            return JSON.readTree(text);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static void run(PostgresTestDatabase database, String resource) throws Exception {
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), resource,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8)));
    }

    private static void seed(PostgresTestDatabase database) {
        List<String> seeds = new ArrayList<>(List.of(IamSeedDataAutoConfiguration.SEED_LOCATIONS));
        seeds.add(IamSeedDataAutoConfiguration.ACCOUNT_SEED_LOCATION);
        for (String seed : seeds) {
            IamSeedDataAutoConfiguration.seedPopulator(new ClassPathResource(seed)).execute(database.dataSource());
        }
    }

    private static void withJpa(PostgresTestDatabase database, Consumer<AssertableApplicationContext> verify,
                                String... properties) {
        new ApplicationContextRunner()
                .withUserConfiguration(QueryFactory.class)
                .withConfiguration(AutoConfigurations.of(CoreDataAutoConfiguration.class))
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .withPropertyValues(
                        "contexa.datasource.url=" + database.dataSource().getJdbcUrl(),
                        "contexa.datasource.username=" + database.dataSource().getUsername(),
                        "contexa.datasource.password=" + database.dataSource().getPassword(),
                        "contexa.datasource.driver-class-name=org.postgresql.Driver")
                .withPropertyValues(properties)
                .run(verify::accept);
    }

    @Configuration(proxyBeanMethods = false)
    static class QueryFactory {

        @Bean(name = "contexaJpaQueryFactory")
        JPAQueryFactory contexaJpaQueryFactory(
                @Qualifier("contexaEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
            return new JPAQueryFactory(SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory));
        }
    }
}
