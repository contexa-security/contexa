package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationResolutionCleanup;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class JdbcOfficialVerificationSnapshotCleanupRepositoryTest {

    @Test
    void ossCleanupDelegatesResolutionAndNeverQueriesEnterpriseResolutionTables() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        OfficialVerificationResolutionCleanup resolutionCleanup =
                mock(OfficialVerificationResolutionCleanup.class);
        JdbcOfficialVerificationSnapshotCleanupRepository repository =
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate, resolutionCleanup);

        repository.deleteDiagnosticPackage("oss", "package-001");

        verify(resolutionCleanup).deleteDiagnosticPackage("oss", "package-001");
        verify(jdbcTemplate, atLeastOnce()).update(
                contains("official_verification_run_batch"), any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("prompt_quality_issue"), any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("prompt_quality_remediation_action"), any(Object[].class));
    }
}
