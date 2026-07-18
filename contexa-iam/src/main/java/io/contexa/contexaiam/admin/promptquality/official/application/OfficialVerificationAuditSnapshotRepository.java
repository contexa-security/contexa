package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;

import java.util.List;

public interface OfficialVerificationAuditSnapshotRepository {
    List<OperatorAuditSnapshot> findByAggregateRunId(String aggregateRunId);
    List<OperatorAuditSnapshot> findByAggregateRunIds(List<String> aggregateRunIds);
}