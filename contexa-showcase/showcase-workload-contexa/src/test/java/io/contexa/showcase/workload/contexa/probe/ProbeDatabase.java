package io.contexa.showcase.workload.contexa.probe;

import io.contexa.showcase.business.company.CompanyGenerator;
import io.contexa.showcase.business.company.CompanyRepository;
import io.contexa.showcase.business.work.WorkDatabase;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Base64;

/**
 * One pgvector PostgreSQL shared by the workload tests, initialised with the same script as the production-shaped
 * stack (infra/postgres/init). It starts when the first Spring context asks for its properties, so test classes
 * skipped for missing Docker never touch it.
 */
final class ProbeDatabase {

    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"))
            .withDatabaseName("showcase_portal")
            .withEnv("TZ", "UTC")
            .withCopyFileToContainer(MountableFile.forHostPath("../infra/postgres/init/01-databases.sql"),
                    "/docker-entrypoint-initdb.d/01-databases.sql");

    /** Fixed company date of the workload tests: a Wednesday, like every anchor (ADR-19). */
    static final LocalDate ANCHOR = LocalDate.of(2026, 9, 30);

    private ProbeDatabase() {
    }

    /** Points the vector, engine datasources and the internal signing key of control D at the test resources. */
    static void register(DynamicPropertyRegistry registry, String signingKey) {
        start();
        registry.add("spring.datasource.url", () -> jdbcUrl("showcase_vector"));
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("contexa.datasource.url", () -> jdbcUrl("showcase_engine"));
        registry.add("contexa.datasource.username", POSTGRES::getUsername);
        registry.add("contexa.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.work.datasource.url", () -> jdbcUrl("showcase_work"));
        registry.add("showcase.work.datasource.username", POSTGRES::getUsername);
        registry.add("showcase.work.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> signingKey);
    }

    static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /** Starts the database once and prepares the business database the way the plain workload does. */
    private static synchronized void start() {
        if (!POSTGRES.isRunning()) {
            POSTGRES.start();
            Flyway.configure()
                    .dataSource(jdbcUrl("showcase_work"), POSTGRES.getUsername(), POSTGRES.getPassword())
                    .locations("classpath:db/migration/work")
                    .load()
                    .migrate();
            WorkDatabase work = new WorkDatabase(new DriverManagerDataSource(jdbcUrl("showcase_work"),
                    POSTGRES.getUsername(), POSTGRES.getPassword()), null);
            new CompanyRepository(work).write(new CompanyGenerator().generate(20261005L, ANCHOR));
        }
    }

    private static String jdbcUrl(String database) {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + database;
    }
}
