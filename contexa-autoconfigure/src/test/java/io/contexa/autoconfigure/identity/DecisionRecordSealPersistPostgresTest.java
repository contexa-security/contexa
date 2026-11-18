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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import io.contexa.contexaiam.admin.web.dashboard.DashboardHourlyStats;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K144: a decision record the audit facade seals and the store writes through JPA reads as sealed. The record's time is
 * the one its hash covers: the store keeps it as the record states it (to the microsecond) and does not set it to the
 * time of the write. Before K144 the auditing listener set it again on persist and every record read as a mismatch.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class DecisionRecordSealPersistPostgresTest {

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static LocalContainerEntityManagerFactoryBean entityManagers;
    private static TransactionTemplate transactions;
    private static AuditLogRepository auditLog;

    @BeforeAll
    static void theCanonicalSchemaWithJpa() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa-decision-seal");
        entityManagers.setPackagesToScan("io.contexa.contexacommon.entity", "io.contexa.contexaiam.domain.entity");
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        transactions = new TransactionTemplate(new JpaTransactionManager(entityManagers.getObject()));
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        auditLog = new JpaRepositoryFactory(entityManager).getRepository(AuditLogRepository.class);
    }

    @AfterAll
    static void close() {
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    @Test
    void decisionRecordsSavedThroughTheFacadeReadAsSealedAndTheDashboardCountsNoBrokenSeal() throws Exception {
        jdbc.update("truncate table ctxa_audit_log, ctxa_dashboard_seal_hourly restart identity cascade");
        HmacEvidenceSigner signer = new HmacEvidenceSigner(Map.of("k1", "0123456789abcdef0123456789abcdef"
                .getBytes(StandardCharsets.UTF_8)), "k1");
        CentralAuditFacade facade = new CentralAuditFacade(auditLog, event -> {
        }, new ObjectMapper());
        facade.setEvidenceSigner(signer);
        LocalDateTime decided = LocalDateTime.now().minusSeconds(3);

        for (int i = 0; i < 3; i++) {
            AuditRecord record = AuditRecord.builder()
                    .timestamp(decided.plusNanos(123_456_789L * (i + 1)))
                    .principalName("alice")
                    .resourceIdentifier("/api/orders/" + i)
                    .eventCategory(AuditEventCategory.SECURITY_DECISION)
                    .action("DECIDE")
                    .decision("ALLOW")
                    .reason("as decided")
                    .build();
            // the decision is written a moment after it was made, as the pipeline writes it
            Thread.sleep(20L);
            transactions.executeWithoutResult(status -> facade.recordSync(record));
        }

        List<AuditLog> stored = transactions.execute(status -> auditLog.findAll().stream()
                .sorted(Comparator.comparing(AuditLog::getId)).toList());
        assertThat(stored).hasSize(3);
        assertThat(stored).extracting(AuditLog::getTimestamp).containsExactly(
                decided.plusNanos(123_456_789L).truncatedTo(ChronoUnit.MICROS),
                decided.plusNanos(246_913_578L).truncatedTo(ChronoUnit.MICROS),
                decided.plusNanos(370_370_367L).truncatedTo(ChronoUnit.MICROS));
        assertThat(stored.get(0).getPreviousRecordHash()).isNull();
        assertThat(stored.get(1).getPreviousRecordHash()).isEqualTo(stored.get(0).getRecordHash());
        assertThat(stored.get(2).getPreviousRecordHash()).isEqualTo(stored.get(1).getRecordHash());
        List<String> hashes = stored.stream().map(AuditLog::getRecordHash).toList();
        assertThat(stored).extracting(record -> DecisionRecordSeal.evaluate(record, signer, hashes::contains))
                .containsExactly(Status.VERIFIED, Status.VERIFIED, Status.VERIFIED);

        // The dashboard's hourly pass over the records' hour, once the hour is over.
        Instant afterTheHour = decided.atZone(ZoneId.systemDefault()).toInstant()
                .truncatedTo(ChronoUnit.HOURS).plus(Duration.ofHours(2));
        Clock clock = Clock.fixed(afterTheHour, ZoneOffset.UTC);
        new DashboardHourlyStats(() -> jdbc, auditLog, new DecisionRecordSealCheck(auditLog, () -> signer), null, clock)
                .rebuildOnce();
        assertThat(jdbc.queryForObject("select coalesce(sum(checked), 0) from ctxa_dashboard_seal_hourly", Long.class))
                .isEqualTo(3L);
        assertThat(new DashboardQueries(() -> jdbc).sealMismatches(afterTheHour.minus(Duration.ofDays(1)),
                afterTheHour)).isZero();
    }

    /** A record that states no time is given the time it is stored at, as before. */
    @Test
    void aRecordWithoutATimeIsGivenTheTimeOfTheWrite() {
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);
        AuditLog saved = transactions.execute(status -> auditLog.save(AuditLog.builder()
                .principalName("bob").resourceIdentifier("/api/none").decision("ALLOW").eventCategory("ADMIN_CHANGE")
                .build()));

        assertThat(saved.getTimestamp()).isAfter(before);
    }
}
