package io.contexa.contexaiam.testsupport;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.contexacore.testsupport.TestStores;
import java.util.Locale;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * A database of its own for each test, created on the PostgreSQL that {@code CONTEXA_TEST_DB_URL} names and dropped on
 * {@link #close()}. Without the variable the test is skipped before anything connects (see {@link TestStores}).
 */
public final class PostgresTestDatabase implements AutoCloseable {

    private static final String TEMPLATE_DATABASE = "contexa_test_template";

    private static boolean templateReady;

    private final String databaseName;
    private final HikariDataSource adminDataSource;
    private final HikariDataSource testDataSource;
    private final JdbcTemplate adminJdbcTemplate;
    private final JdbcTemplate jdbcTemplate;

    private PostgresTestDatabase(
            String databaseName,
            HikariDataSource adminDataSource,
            HikariDataSource testDataSource) {
        this.databaseName = databaseName;
        this.adminDataSource = adminDataSource;
        this.testDataSource = testDataSource;
        this.adminJdbcTemplate = new JdbcTemplate(adminDataSource);
        this.jdbcTemplate = new JdbcTemplate(testDataSource);
    }

    public static PostgresTestDatabase migrated() {
        return create(true);
    }

    public static PostgresTestDatabase empty() {
        return create(false);
    }

    private static PostgresTestDatabase create(boolean migrated) {
        TestStores.Database settings = TestStores.database();
        HikariDataSource adminDataSource = dataSource(
                urlForDatabase(settings.url(), "postgres"),
                settings.username(),
                settings.password(),
                "pqa-test-admin");
        JdbcTemplate admin = new JdbcTemplate(adminDataSource);
        if (migrated) {
            ensureTemplate(admin, settings);
        }

        String databaseName = "contexa_test_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        admin.execute("create database " + databaseName
                + (migrated ? " template " + TEMPLATE_DATABASE : ""));

        HikariDataSource testDataSource = dataSource(
                urlForDatabase(settings.url(), databaseName),
                settings.username(),
                settings.password(),
                databaseName);
        return new PostgresTestDatabase(databaseName, adminDataSource, testDataSource);
    }

    private static synchronized void ensureTemplate(JdbcTemplate admin, TestStores.Database settings) {
        if (templateReady) {
            return;
        }
        Boolean exists = admin.queryForObject(
                "select exists(select 1 from pg_database where datname = ?)",
                Boolean.class,
                TEMPLATE_DATABASE);
        if (!Boolean.TRUE.equals(exists)) {
            admin.execute("create database " + TEMPLATE_DATABASE);
        }

        try (HikariDataSource templateDataSource = dataSource(
                urlForDatabase(settings.url(), TEMPLATE_DATABASE),
                settings.username(),
                settings.password(),
                "pqa-test-template")) {
            Flyway.configure()
                    .dataSource(templateDataSource)
                    .locations("classpath:db/migration")
                    .baselineOnMigrate(false)
                    .validateOnMigrate(true)
                    .outOfOrder(false)
                    .cleanDisabled(true)
                    .load()
                    .migrate();
        }
        templateReady = true;
    }

    public JdbcTemplate jdbcTemplate() {
        return jdbcTemplate;
    }


    public HikariDataSource dataSource() {
        return testDataSource;
    }

    @Override
    public void close() {
        testDataSource.close();
        adminJdbcTemplate.queryForList("""
                select pg_terminate_backend(pid)
                  from pg_stat_activity
                 where datname = ?
                   and pid <> pg_backend_pid()
                """, databaseName);
        adminJdbcTemplate.execute("drop database if exists " + databaseName);
        adminDataSource.close();
    }

    private static HikariDataSource dataSource(
            String url,
            String username,
            String password,
            String poolName) {
        HikariConfig config = new HikariConfig();
        config.setDriverClassName("org.postgresql.Driver");
        config.setJdbcUrl(url);
        config.setUsername(username);
        config.setPassword(password);
        config.setPoolName(poolName);
        config.setMaximumPoolSize(8);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(5_000L);
        return new HikariDataSource(config);
    }

    private static String urlForDatabase(String url, String databaseName) {
        int queryIndex = url.indexOf('?');
        String base = queryIndex >= 0 ? url.substring(0, queryIndex) : url;
        String query = queryIndex >= 0 ? url.substring(queryIndex) : "";
        int slash = base.lastIndexOf('/');
        if (slash < "jdbc:postgresql://".length()) {
            throw new IllegalArgumentException("PostgreSQL JDBC URL must include a database name: " + url);
        }
        return base.substring(0, slash + 1) + databaseName + query;
    }
}
