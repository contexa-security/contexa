package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;

import java.util.List;

public interface OfficialVerificationPurposeEvidenceRepository {
    List<OperatorPurposeEvidence> findByAggregateRunId(String aggregateRunId);
    List<OperatorPurposeEvidence> findByAggregateRunIds(List<String> aggregateRunIds);
}