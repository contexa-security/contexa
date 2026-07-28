package io.contexa.contexaiam.admin.promptquality.official.common;

import io.contexa.contexacore.verification.metric.OfficialVerificationDefinitionCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationDefinitionCatalog.CheckSeed;
import io.contexa.contexacore.verification.metric.OfficialVerificationDefinitionCatalog.MetricSeed;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import java.util.Set;

/** Persists and verifies the canonical final-prompt contract's derived definition view. */
public final class OfficialVerificationDefinitionCatalogWriter {

    private static final String UPSERT_METRIC = """
            insert into official_verification_metric_definition
                (metric_code, definition_version, metric_name, metric_group, purpose,
                 evidence_contract, blocking_scope, is_active)
            values (?, ?, ?, ?, ?, ?, ?, true)
            on conflict (metric_code, definition_version) do update set
                metric_name = excluded.metric_name,
                metric_group = excluded.metric_group,
                purpose = excluded.purpose,
                evidence_contract = excluded.evidence_contract,
                blocking_scope = excluded.blocking_scope,
                is_active = true
            """;

    private static final String UPSERT_CHECK = """
            insert into official_verification_metric_check_definition
                (metric_code, check_code, definition_version, check_label, expected_value,
                 evidence_source, severity, remediation_owner, is_active)
            values (?, ?, ?, ?, ?, ?, ?, ?, true)
            on conflict (metric_code, check_code, definition_version) do update set
                check_label = excluded.check_label,
                expected_value = excluded.expected_value,
                evidence_source = excluded.evidence_source,
                severity = excluded.severity,
                remediation_owner = excluded.remediation_owner,
                is_active = true
            """;

    private final DataSource dataSource;

    public OfficialVerificationDefinitionCatalogWriter(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public CatalogSnapshot upsertAndVerify() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                upsertMetrics(connection);
                upsertChecks(connection);
                CatalogSnapshot snapshot = verify(connection);
                connection.commit();
                return snapshot;
            } catch (Exception error) {
                connection.rollback();
                if (error instanceof SQLException sqlException) {
                    throw sqlException;
                }
                throw new SQLException("Official verification definition catalog update failed", error);
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }
    }

    public CatalogSnapshot verify() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            return verify(connection);
        }
    }

    private void upsertMetrics(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPSERT_METRIC)) {
            for (MetricSeed metric : OfficialVerificationDefinitionCatalog.metrics()) {
                statement.setString(1, metric.code());
                statement.setString(2, OfficialVerificationDefinitionCatalog.VERSION);
                statement.setString(3, metric.name());
                statement.setString(4, metric.group());
                statement.setString(5, metric.purpose());
                statement.setString(6, metric.evidenceContract());
                statement.setString(7, metric.blockingScope());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private void upsertChecks(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPSERT_CHECK)) {
            for (CheckSeed check : OfficialVerificationDefinitionCatalog.checks()) {
                statement.setString(1, check.metricCode());
                statement.setString(2, check.checkCode());
                statement.setString(3, OfficialVerificationDefinitionCatalog.VERSION);
                statement.setString(4, check.label());
                statement.setString(5, check.expectedValue());
                statement.setString(6, check.evidenceSource());
                statement.setString(7, check.severity());
                statement.setString(8, check.remediationOwner());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private CatalogSnapshot verify(Connection connection) throws SQLException {
        Set<String> expectedMetricKeys = new LinkedHashSet<>();
        OfficialVerificationDefinitionCatalog.metrics().forEach(metric -> expectedMetricKeys.add(metric.code()));
        Set<String> expectedCheckKeys = new LinkedHashSet<>();
        OfficialVerificationDefinitionCatalog.checks().forEach(
                check -> expectedCheckKeys.add(check.metricCode() + "|" + check.checkCode()));

        Set<String> actualMetricKeys = queryKeys(connection,
                "select metric_code from official_verification_metric_definition "
                        + "where definition_version = ? and is_active = true order by metric_code",
                false);
        Set<String> actualCheckKeys = queryKeys(connection,
                "select metric_code, check_code from official_verification_metric_check_definition "
                        + "where definition_version = ? and is_active = true order by metric_code, check_code",
                true);
        assertExact("metric", expectedMetricKeys, actualMetricKeys);
        assertExact("check", expectedCheckKeys, actualCheckKeys);
        return new CatalogSnapshot(
                OfficialVerificationDefinitionCatalog.VERSION,
                OfficialVerificationDefinitionCatalog.checksum(),
                actualMetricKeys,
                actualCheckKeys);
    }

    private Set<String> queryKeys(Connection connection, String sql, boolean composite) throws SQLException {
        Set<String> keys = new LinkedHashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, OfficialVerificationDefinitionCatalog.VERSION);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    String key = resultSet.getString(1);
                    keys.add(composite ? key + "|" + resultSet.getString(2) : key);
                }
            }
        }
        return keys;
    }

    private void assertExact(String type, Set<String> expected, Set<String> actual) {
        if (expected.equals(actual)) {
            return;
        }
        Set<String> missing = new LinkedHashSet<>(expected);
        missing.removeAll(actual);
        Set<String> unexpected = new LinkedHashSet<>(actual);
        unexpected.removeAll(expected);
        throw new IllegalStateException("Official verification " + type + " catalog mismatch. missing="
                + missing + ", unexpected=" + unexpected);
    }

    public record CatalogSnapshot(
            String version,
            String checksum,
            Set<String> metricKeys,
            Set<String> checkKeys) {

        public CatalogSnapshot {
            metricKeys = Set.copyOf(metricKeys);
            checkKeys = Set.copyOf(checkKeys);
        }
    }
}
