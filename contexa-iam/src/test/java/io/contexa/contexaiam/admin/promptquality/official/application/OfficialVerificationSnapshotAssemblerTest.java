package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationSnapshotAssemblerTest {

    private final OfficialVerificationSnapshotAssembler assembler = new OfficialVerificationSnapshotAssembler();

    @Test
    void assembleNormalizesNullCollectionsAndCopiesMutableInput() {
        List<OperatorPurposeEvidence> purposeEvidence = new ArrayList<>();
        purposeEvidence.add(purposeEvidence("run-1", "signal-1"));

        OperatorSnapshot snapshot = assembler.assemble(
                batch("run-1"),
                null,
                null,
                null,
                null,
                purposeEvidence,
                null);
        purposeEvidence.clear();

        assertThat(snapshot.metrics()).isEmpty();
        assertThat(snapshot.findings()).isEmpty();
        assertThat(snapshot.remediationGroups()).isEmpty();
        assertThat(snapshot.actualPromptProblems()).isEmpty();
        assertThat(snapshot.auditSnapshots()).isEmpty();
        assertThat(snapshot.purposeEvidence())
                .extracting(OperatorPurposeEvidence::signalKey)
                .containsExactly("signal-1");
    }

    @Test
    void assembleAllKeepsChildRowsInsideTheirAggregateRun() {
        List<OperatorSnapshot> snapshots = assembler.assembleAll(
                List.of(batch("run-1"), batch("run-2")),
                null,
                null,
                null,
                null,
                Map.of(
                        "run-1", List.of(purposeEvidence("run-1", "signal-1")),
                        "run-2", List.of(purposeEvidence("run-2", "signal-2"))),
                null);

        assertThat(snapshots).hasSize(2);
        assertThat(snapshots.get(0).batch().aggregateRunId()).isEqualTo("run-1");
        assertThat(snapshots.get(0).purposeEvidence())
                .extracting(OperatorPurposeEvidence::signalKey)
                .containsExactly("signal-1");
        assertThat(snapshots.get(1).batch().aggregateRunId()).isEqualTo("run-2");
        assertThat(snapshots.get(1).purposeEvidence())
                .extracting(OperatorPurposeEvidence::signalKey)
                .containsExactly("signal-2");
    }

    private OperatorRunBatch batch(String aggregateRunId) {
        return new OperatorRunBatch(
                aggregateRunId,
                "package-1",
                "certificate-1",
                "case-1",
                "PACKAGE",
                1,
                1,
                1,
                0,
                0,
                0,
                "PASS",
                false,
                null,
                "prompt-hash",
                "context-hash",
                "AVAILABLE",
                "template-resource",
                "actual-resource",
                "/resource/{id}",
                "/resource/1",
                "GET",
                "catalog-v1",
                Instant.parse("2026-07-15T00:00:00Z"));
    }

    private OperatorPurposeEvidence purposeEvidence(String aggregateRunId, String signalKey) {
        return new OperatorPurposeEvidence(
                aggregateRunId,
                "package-1",
                "metric-1",
                "check-1",
                "contract-v1",
                signalKey,
                "SYSTEM",
                "value",
                "hash",
                "interpretation",
                "PASS",
                true,
                "RUNTIME",
                List.of("fact"),
                List.of("context"),
                Instant.parse("2026-07-15T00:00:00Z"));
    }
}