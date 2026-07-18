package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView.SealedEvidenceCheckView;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView.SealedEvidenceEventView;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcOfficialVerificationRunStoreTest {

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    void listDetailedByPackageIdMergesPackageColumnAndEvidenceReferenceRows() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        JdbcOfficialVerificationRunStore store = new JdbcOfficialVerificationRunStore(jdbcOperations, new ObjectMapper());
        OfficialVerificationRunView direct = run("osev-sep-mixed-001-eir", "EIR", "sep-mixed-001");
        OfficialVerificationRunView fallback = run("osev-sep-mixed-001-ccr", "CCR", "sep-mixed-001");

        when(jdbcOperations.query(contains("where package_id = ?"), any(RowMapper.class), eq("sep-mixed-001")))
                .thenReturn(List.of(direct));
        when(jdbcOperations.query(
                contains("evidence_references_json like"),
                any(RowMapper.class),
                eq("%\"packageId\"%"),
                eq("%\"sep-mixed-001\"%")))
                .thenReturn(List.of(direct, fallback));

        List<OfficialVerificationRunView> runs = store.listDetailedByPackageId("sep-mixed-001");

        assertThat(runs).extracting(OfficialVerificationRunView::runId)
                .containsExactly("osev-sep-mixed-001-eir", "osev-sep-mixed-001-ccr");
    }

    @Test
    void saveDetailedPersistsMainAndNormalizedChildrenThroughSingleJdbcOwner() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        JdbcOfficialVerificationRunStore store = new JdbcOfficialVerificationRunStore(jdbcOperations, new ObjectMapper());
        Instant startedAt = Instant.parse("2026-07-15T00:00:00Z");
        Instant completedAt = Instant.parse("2026-07-15T00:00:01Z");
        OfficialVerificationRunRecord record = new OfficialVerificationRunRecord(
                "run-1",
                "MTR",
                "OFFICIAL",
                "COMPLETED",
                "admin",
                startedAt,
                startedAt,
                completedAt,
                "completed",
                Map.of("requestId", "request-1", "packageId", "package-1"));
        OfficialVerificationRunView view = new SealedEvidenceOfficialRunView(
                "run-1",
                1,
                "MTR",
                "Metric traceability",
                "request-1",
                100.0d,
                1,
                1,
                5L,
                "COMPLETED",
                "success",
                "completed",
                "2026-07-15 09:00:00",
                "2026-07-15 09:00:01",
                List.of(new SealedEvidenceCheckView(
                        "CHECK_1", "Check 1", "expected", "actual", true, "runtime",
                        "INFO", "", "PQA_RUNTIME", "", "", "")),
                Map.of("requestId", "request-1"),
                Map.of("event", "captured"),
                Map.of("promptHash", "sha256:prompt"),
                Map.of("analysis", "complete"),
                List.of(new SealedEvidenceEventView("CAPTURED", "runtime", "COMPLETED", "/api/resource")),
                Map.of("packageId", "package-1", "aggregateRunId", "aggregate-1"));

        store.saveDetailed("admin", record, view);

        verify(jdbcOperations, atLeastOnce()).update(contains("insert into verification_run_ledger"), any(Object[].class));
        verify(jdbcOperations).update(contains("insert into verification_run_round_ledger"), any(Object[].class));
        verify(jdbcOperations).update(contains("insert into verification_run_check_ledger"), any(Object[].class));
        verify(jdbcOperations, atLeastOnce()).update(contains("insert into verification_run_fact_ledger"), any(Object[].class));
        verify(jdbcOperations).update(contains("insert into verification_run_event_ledger"), any(Object[].class));
        verify(jdbcOperations).update(contains("insert into verification_raw_evidence_artifact_ledger"), any(Object[].class));
    }
    private OfficialVerificationRunView run(String runId, String metricCode, String packageId) {
        return new SealedEvidenceOfficialRunView(
                runId,
                1,
                metricCode,
                metricCode,
                "req-001",
                100.0d,
                1,
                1,
                10L,
                "PASSED",
                "success",
                "ok",
                "2026-07-06 10:00:00",
                "2026-07-06 10:00:01",
                List.of(),
                Map.of("requestId", "req-001"),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of("packageId", packageId, "aggregateRunId", "osev-sep-mixed-001"));
    }
}