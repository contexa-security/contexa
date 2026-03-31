package io.contexa.sandbox.fullstack.prompt;

import org.springframework.test.context.DynamicPropertyRegistry;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.UUID;

/**
 * sandbox 전용 PostgreSQL schema 격리 지원.
 *
 * 목적:
 * 1. starter 애플리케이션이 실제 PostgreSQL/pgvector를 그대로 사용하게 한다.
 * 2. 하지만 테스트가 public schema나 운영 데이터에 손대지 않게 한다.
 * 3. 테스트가 끝나면 schema 전체를 drop 해서 side effect를 남기지 않는다.
 */
public final class SandboxPostgresqlSchemaSupport {

    private static final String JDBC_URL = "jdbc:postgresql://localhost:5432/contexa";
    private static final String USERNAME = "contexa";
    private static final String PASSWORD = "contexa1234!@#";

    private final String schemaName;

    private SandboxPostgresqlSchemaSupport(String schemaName) {
        this.schemaName = schemaName;
    }

    public static SandboxPostgresqlSchemaSupport create() {
        String schemaName = "sandbox_fullstack_prompt_" +
                UUID.randomUUID().toString().replace("-", "").substring(0, 12).toLowerCase(Locale.ROOT);
        SandboxPostgresqlSchemaSupport support = new SandboxPostgresqlSchemaSupport(schemaName);
        support.createSchema();
        return support;
    }

    public String schemaName() {
        return schemaName;
    }

    public void register(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> JDBC_URL + "?currentSchema=" + schemaName + ",public");
        registry.add("spring.datasource.username", () -> USERNAME);
        registry.add("spring.datasource.password", () -> PASSWORD);
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.jpa.defer-datasource-initialization", () -> "true");
        registry.add("spring.sql.init.mode", () -> "never");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> schemaName);
        registry.add("spring.datasource.hikari.connection-init-sql",
                () -> "SET search_path TO " + schemaName + ",public");
    }

    public void dropQuietly() {
        try (Connection connection = openConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS " + schemaName + " CASCADE");
        } catch (SQLException ignored) {
            // sandbox 정리 단계 실패는 후속 테스트 원인을 가리지 않기 위해 조용히 무시한다.
        }
    }

    private void createSchema() {
        try (Connection connection = openConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA IF NOT EXISTS " + schemaName);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS %s.audit_log (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL,
                        principal_name VARCHAR(255) NOT NULL,
                        resource_identifier VARCHAR(512) NOT NULL,
                        action VARCHAR(100),
                        decision VARCHAR(50) NOT NULL,
                        reason VARCHAR(1024),
                        outcome VARCHAR(50),
                        resource_uri VARCHAR(1024),
                        client_ip VARCHAR(45),
                        session_id VARCHAR(128),
                        details TEXT,
                        event_category VARCHAR(50),
                        user_agent VARCHAR(512),
                        http_method VARCHAR(10),
                        request_uri VARCHAR(2048),
                        risk_score DOUBLE PRECISION,
                        event_source VARCHAR(50),
                        correlation_id VARCHAR(64)
                    )
                    """.formatted(schemaName));
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS %s.one_time_tokens (
                        token_value VARCHAR(255) NOT NULL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        expires_at TIMESTAMP NOT NULL
                    )
                    """.formatted(schemaName));
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to create sandbox PostgreSQL schema: " + schemaName, exception);
        }
    }

    private Connection openConnection() throws SQLException {
        return DriverManager.getConnection(JDBC_URL, USERNAME, PASSWORD);
    }
}
