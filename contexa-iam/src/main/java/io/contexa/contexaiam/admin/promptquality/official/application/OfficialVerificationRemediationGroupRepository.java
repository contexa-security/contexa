package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;

import java.util.List;

public interface OfficialVerificationRemediationGroupRepository {
    List<OperatorRemediationGroup> findByAggregateRunId(String aggregateRunId);
    List<OperatorRemediationGroup> findByAggregateRunIds(List<String> aggregateRunIds);
}