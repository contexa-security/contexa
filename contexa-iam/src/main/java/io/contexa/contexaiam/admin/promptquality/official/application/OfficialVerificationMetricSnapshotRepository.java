package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;

import java.util.List;

public interface OfficialVerificationMetricSnapshotRepository {
    List<OperatorMetricSnapshot> findByAggregateRunId(String aggregateRunId);
    List<OperatorMetricSnapshot> findByAggregateRunIds(List<String> aggregateRunIds);
}