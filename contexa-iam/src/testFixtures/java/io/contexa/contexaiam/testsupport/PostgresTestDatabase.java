package io.contexa.contexaiam.testsupport;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.contexa.contexacore.testsupport.TestStores;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * A database of its own for each test, created on the PostgreSQL that {@code CONTEXA_TEST_DB_URL} names and dropped on
 * {@link #close()}. Without the variable the test is skipped before anything connects (see {@link TestStores}).
 */
public final class PostgresTestDatabase implements AutoCloseable {

    private static final String TEMPLATE_DATABASE = "contexa_test_template";
    private static final String OSS_SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String BASELINE_PROPERTIES = "db/baseline/baseline.properties";

    private static boolean templateReady;
    private static String templateDatabase = TEMPLATE_DATABASE;

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
        try {
            if (migrated) {
                ensureTemplate(admin, settings);
            }

            String databaseName = "contexa_test_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
            admin.execute("create database " + databaseName
                    + (migrated ? " template " + templateDatabase : ""));

            HikariDataSource testDataSource = dataSource(
                    urlForDatabase(settings.url(), databaseName),
                    settings.username(),
                    settings.password(),
                    databaseName);
            return new PostgresTestDatabase(databaseName, adminDataSource, testDataSource);
        } catch (RuntimeException failure) {
            // a test that cannot get its database holds no connection of the shared server
            adminDataSource.close();
            throw failure;
        }
    }

    /**
     * The template every migrated test database is copied from, made once per set of schema files the way an
     * application makes its database: the open-source schema ({@value #OSS_SCHEMA}), then, when the class path carries
     * an enterprise baseline ({@value #BASELINE_PROPERTIES}), the baseline files recorded at the baseline version, then
     * the migrations after it. The enterprise migrations up to the baseline were written on top of an older open-source
     * schema and cannot be replayed on a new database (see the enterprise {@code EnterpriseBaseline}).
     * <p>
     * Its name carries a fingerprint of those files, so a change of them makes a new template; it is built under a
     * temporary name and renamed when complete, so a template that failed half way is never used.
     */
    private static synchronized void ensureTemplate(JdbcTemplate admin, TestStores.Database settings) {
        if (templateReady) {
            return;
        }
        SchemaFiles files = SchemaFiles.load();
        templateDatabase = TEMPLATE_DATABASE + "_" + files.fingerprint();
        Boolean exists = admin.queryForObject(
                "select exists(select 1 from pg_database where datname = ?)",
                Boolean.class,
                templateDatabase);
        if (!Boolean.TRUE.equals(exists)) {
            String building = templateDatabase + "_b" + UUID.randomUUID().toString().substring(0, 8);
            admin.execute("create database " + building);
            try {
                try (HikariDataSource target = dataSource(
                        urlForDatabase(settings.url(), building),
                        settings.username(),
                        settings.password(),
                        "pqa-test-template")) {
                    files.applyTo(target);
                }
                admin.execute("alter database " + building + " rename to " + templateDatabase);
            } catch (RuntimeException failure) {
                admin.execute("drop database if exists " + building);
                throw failure;
            }
        }
        templateReady = true;
    }

    /** The schema files on the class path, in the order an application applies them. */
    private record SchemaFiles(String ossSchema, String baselineVersion, String baselineSql, List<String> migrations) {

        static SchemaFiles load() {
            PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
            try {
                Resource oss = resolver.getResource("classpath:" + OSS_SCHEMA);
                String ossSchema = oss.exists() ? oss.getContentAsString(StandardCharsets.UTF_8) : "";
                Resource properties = resolver.getResource("classpath:" + BASELINE_PROPERTIES);
                String version = null;
                StringBuilder baseline = new StringBuilder();
                if (properties.exists()) {
                    Properties values = new Properties();
                    values.load(new StringReader(properties.getContentAsString(StandardCharsets.UTF_8)));
                    version = values.getProperty("version").trim();
                    List<Resource> sql = new ArrayList<>(List.of(resolver.getResources("classpath*:db/baseline/*.sql")));
                    sql.sort(Comparator.comparing(Resource::getFilename));
                    for (Resource file : sql) {
                        baseline.append(file.getContentAsString(StandardCharsets.UTF_8)).append('\n');
                    }
                }
                List<String> migrations = new ArrayList<>();
                for (Resource migration : resolver.getResources("classpath*:db/migration/*.sql")) {
                    migrations.add(migration.getFilename() + ":" + migration.contentLength());
                }
                migrations.sort(Comparator.naturalOrder());
                return new SchemaFiles(ossSchema, version, baseline.toString(), migrations);
            } catch (IOException e) {
                throw new UncheckedIOException("The schema files of the test database could not be read", e);
            }
        }

        String fingerprint() {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                for (String part : List.of(ossSchema, String.valueOf(baselineVersion), baselineSql,
                        String.join("\n", migrations))) {
                    digest.update(part.getBytes(StandardCharsets.UTF_8));
                    digest.update((byte) 0);
                }
                return HexFormat.of().formatHex(digest.digest()).substring(0, 12);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        void applyTo(DataSource target) {
            if (!ossSchema.isBlank()) {
                executeAll(target, ossSchema);
            }
            FluentConfiguration flyway = Flyway.configure()
                    .dataSource(target)
                    .locations("classpath:db/migration")
                    .baselineOnMigrate(false)
                    .validateOnMigrate(true)
                    .outOfOrder(false)
                    .cleanDisabled(true);
            if (baselineVersion != null) {
                executeAll(target, baselineSql);
                flyway.baselineVersion(baselineVersion).baselineDescription("Enterprise baseline").load().baseline();
            }
            flyway.load().migrate();
        }

        /** One script in one transaction, as the application sends its schema and its baseline. */
        private static void executeAll(DataSource target, String sql) {
            try (Connection connection = target.getConnection()) {
                connection.setAutoCommit(false);
                try (Statement statement = connection.createStatement()) {
                    statement.setEscapeProcessing(false);
                    statement.execute(sql);
                    connection.commit();
                } catch (SQLException | RuntimeException failure) {
                    connection.rollback();
                    throw failure;
                }
            } catch (SQLException e) {
                throw new IllegalStateException("The schema of the test database could not be made", e);
            }
        }
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
