package io.contexa.showcase.portal;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The portal schema migrates on an empty database, validates on a second run and enforces its constraints.
 * Skipped when Docker is unavailable; the showcase CI and the phase gates run it with Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
class PortalSchemaMigrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static Flyway flyway() {
        return Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/portal")
                .cleanDisabled(true)
                .load();
    }

    @Test
    void migratesEmptyDatabaseAndValidatesOnRestart() {
        assertThat(flyway().migrate().success).isTrue();
        flyway().validate();
        assertThat(flyway().migrate().migrationsExecuted).isZero();
    }

    @Test
    void executionSpecRejectsUnknownModeAndDuplicateHash() {
        flyway().migrate();
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
        String hash = "a".repeat(64);
        String insert = "insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode, "
                + "endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, rule_version, "
                + "time_zone) values (?, ?, 'c', 'e', ?, '{}'::jsonb, 'm', 'em', 1024, ?, ?, 'UTC')";

        jdbc.update(insert, UUID.randomUUID(), hash, "ENFORCE", hash, hash);

        assertThatThrownBy(() -> jdbc.update(insert, UUID.randomUUID(), hash, "ENFORCE", hash, hash))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update(insert, UUID.randomUUID(), "b".repeat(64), "LENIENT", hash, hash))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
