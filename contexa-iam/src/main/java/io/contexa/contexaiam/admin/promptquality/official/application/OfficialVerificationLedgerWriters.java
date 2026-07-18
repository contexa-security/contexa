package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

public final class OfficialVerificationLedgerWriters {

    private final OfficialVerificationActualPromptProblemWriter actualPromptProblemWriter;
    private final OfficialVerificationPromptQualityIssueSynchronizer promptQualityIssueSynchronizer;
    private final OfficialVerificationMetricPurposeWriter metricPurposeWriter;
    private final OfficialVerificationMetricPurposeEvidenceWriter metricPurposeEvidenceWriter;
    private final OfficialVerificationPromptSignalWriter promptSignalWriter;
    private final OfficialVerificationActualPromptProblemLinker actualPromptProblemLinker;
    private final OfficialVerificationPromptLineageWriter promptLineageWriter;
    private final OfficialVerificationPromptFieldStateWriter promptFieldStateWriter;

    public OfficialVerificationLedgerWriters(
            OfficialVerificationActualPromptProblemWriter actualPromptProblemWriter,
            OfficialVerificationPromptQualityIssueSynchronizer promptQualityIssueSynchronizer,
            OfficialVerificationMetricPurposeWriter metricPurposeWriter,
            OfficialVerificationMetricPurposeEvidenceWriter metricPurposeEvidenceWriter,
            OfficialVerificationPromptSignalWriter promptSignalWriter,
            OfficialVerificationActualPromptProblemLinker actualPromptProblemLinker,
            OfficialVerificationPromptLineageWriter promptLineageWriter,
            OfficialVerificationPromptFieldStateWriter promptFieldStateWriter) {
        this.actualPromptProblemWriter = Objects.requireNonNull(actualPromptProblemWriter, "actualPromptProblemWriter");
        this.promptQualityIssueSynchronizer = Objects.requireNonNull(
                promptQualityIssueSynchronizer, "promptQualityIssueSynchronizer");
        this.metricPurposeWriter = Objects.requireNonNull(metricPurposeWriter, "metricPurposeWriter");
        this.metricPurposeEvidenceWriter = Objects.requireNonNull(
                metricPurposeEvidenceWriter, "metricPurposeEvidenceWriter");
        this.promptSignalWriter = Objects.requireNonNull(promptSignalWriter, "promptSignalWriter");
        this.actualPromptProblemLinker = Objects.requireNonNull(actualPromptProblemLinker, "actualPromptProblemLinker");
        this.promptLineageWriter = Objects.requireNonNull(promptLineageWriter, "promptLineageWriter");
        this.promptFieldStateWriter = Objects.requireNonNull(promptFieldStateWriter, "promptFieldStateWriter");
    }

    public OfficialVerificationActualPromptProblemWriter actualPromptProblem() { return actualPromptProblemWriter; }
    public OfficialVerificationPromptQualityIssueSynchronizer promptQualityIssue() { return promptQualityIssueSynchronizer; }
    public OfficialVerificationMetricPurposeWriter metricPurpose() { return metricPurposeWriter; }
    public OfficialVerificationMetricPurposeEvidenceWriter metricPurposeEvidence() { return metricPurposeEvidenceWriter; }
    public OfficialVerificationPromptSignalWriter promptSignal() { return promptSignalWriter; }
    public OfficialVerificationActualPromptProblemLinker actualPromptProblemLinker() { return actualPromptProblemLinker; }
    public OfficialVerificationPromptLineageWriter promptLineage() { return promptLineageWriter; }
    public OfficialVerificationPromptFieldStateWriter promptFieldState() { return promptFieldStateWriter; }
}