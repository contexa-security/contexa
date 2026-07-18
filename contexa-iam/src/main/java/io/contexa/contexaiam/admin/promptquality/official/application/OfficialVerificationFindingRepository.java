package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;

import java.util.List;

public interface OfficialVerificationFindingRepository {
    List<OperatorFinding> findByAggregateRunId(String aggregateRunId);
    List<OperatorFinding> findByAggregateRunIds(List<String> aggregateRunIds);
}