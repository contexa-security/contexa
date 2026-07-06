package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class OfficialVerificationOperatorSnapshotServiceTest {

    private static final String PACKAGE_ID = "sealed-request-evidence-001";

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Test
    void replaceDiagnosticsForQualityTargetDoesNotDeleteCoreOfficialRunLedger() {
        OfficialVerificationOperatorSnapshotService service =
                new OfficialVerificationOperatorSnapshotService(jdbcTemplate, new ObjectMapper());

        assertThat(service.replaceDiagnosticsForQualityTarget(
                PACKAGE_ID,
                "resource-001",
                "/resource/001",
                "GET"))
                .isEmpty();

        verify(jdbcTemplate, atLeastOnce()).update(
                contains("delete from official_verification_metric_execution_ledger"),
                eq(PACKAGE_ID));
        verify(jdbcTemplate, atLeastOnce()).update(
                contains("delete from official_verification_run_batch where package_id = ?"),
                eq(PACKAGE_ID));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_run_round_ledger where run_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_run_check_ledger where run_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_run_fact_ledger where run_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_run_event_ledger where run_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_raw_evidence_artifact_ledger where run_id = ?"),
                any(Object[].class));
        verify(jdbcTemplate, never()).update(
                contains("delete from verification_run_ledger where run_id = ?"),
                any(Object[].class));
    }
}