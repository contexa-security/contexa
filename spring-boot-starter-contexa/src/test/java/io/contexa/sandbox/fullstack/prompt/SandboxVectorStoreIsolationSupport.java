package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * sandbox 전용 vector_store 격리 지원기.
 *
 * 목적:
 * - replay/benchmark가 남긴 sandbox 사용자 메모리를 다음 실행 전에 자동 정리한다.
 * - 테스트 종료 후에도 public.vector_store에 sandbox 흔적이 남지 않게 한다.
 * - vector search cache를 함께 비워, 이전 실행 검색 결과가 다음 실행에 재사용되지 않게 한다.
 */
public class SandboxVectorStoreIsolationSupport {

    private static final String JDBC_URL = "jdbc:postgresql://localhost:5432/contexa";
    private static final String USERNAME = "contexa";
    private static final String PASSWORD = "contexa1234!@#";

    private static final String DELETE_REPLAY_ARTIFACTS_SQL = """
            DELETE FROM public.vector_store
            WHERE COALESCE(metadata ->> 'userId', '') LIKE 'sandbox-admin-%%@example.com'
               OR COALESCE(metadata ->> 'userId', '') LIKE 'benchmark-admin-%%@example.com'
               OR COALESCE(metadata ->> 'userId', '') LIKE 'sandbox-seed-%%@example.com'
            """;

    private final JdbcTemplate jdbcTemplate;
    private final VectorStoreCacheLayer vectorStoreCacheLayer;

    public SandboxVectorStoreIsolationSupport(
            JdbcTemplate jdbcTemplate,
            VectorStoreCacheLayer vectorStoreCacheLayer) {
        this.jdbcTemplate = jdbcTemplate;
        this.vectorStoreCacheLayer = vectorStoreCacheLayer;
    }

    public void prepareCleanReplayRun() {
        deleteReplayArtifacts(jdbcTemplate);
        invalidateVectorCache();
    }

    public void cleanupAfterReplayRun() {
        deleteReplayArtifacts(jdbcTemplate);
        invalidateVectorCache();
    }

    public static void cleanupReplayArtifactsInDatabase() {
        try (Connection connection = DriverManager.getConnection(JDBC_URL, USERNAME, PASSWORD);
             PreparedStatement statement = connection.prepareStatement(DELETE_REPLAY_ARTIFACTS_SQL)) {
            statement.executeUpdate();
        } catch (SQLException ignored) {
            // sandbox 정리는 테스트 종료 보조 장치이므로, cleanup 실패가 전체 테스트 실패 원인이 되지 않게 한다.
        }
    }

    private void deleteReplayArtifacts(JdbcTemplate template) {
        try {
            template.update(DELETE_REPLAY_ARTIFACTS_SQL);
        } catch (DataAccessException ignored) {
            cleanupReplayArtifactsInDatabase();
        }
    }

    private void invalidateVectorCache() {
        if (vectorStoreCacheLayer != null) {
            vectorStoreCacheLayer.invalidateAll();
        }
    }
}
