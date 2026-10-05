package io.contexa.showcase.workload.plain;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The business schema owned by the plain workload migrates on an empty database, validates on a second
 * run and keeps its referential integrity. Skipped when Docker is unavailable.
 */
@Testcontainers(disabledWithoutDocker = true)
class WorkSchemaMigrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static Flyway flyway() {
        return Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/work")
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
    void employeeRequiresAnExistingRole() {
        flyway().migrate();
        JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
        jdbc.update("insert into role (role_key, display_name_en, display_name_ko) values ('ENGINEER', 'Engineer', '엔지니어')");
        jdbc.update("insert into employee (employee_key, role_key, display_name, department) "
                + "values ('engineer-k', 'ENGINEER', 'Engineer K', 'Design')");

        assertThatThrownBy(() -> jdbc.update("insert into employee (employee_key, role_key, display_name, department) "
                + "values ('ghost', 'UNKNOWN', 'Ghost', 'None')"))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("select count(*) from employee", Integer.class)).isEqualTo(1);
    }
}
