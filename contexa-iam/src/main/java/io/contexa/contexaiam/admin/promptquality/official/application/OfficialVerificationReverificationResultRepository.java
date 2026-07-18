package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorReverificationResult;

import java.util.List;

public interface OfficialVerificationReverificationResultRepository {
    List<OperatorReverificationResult> findBySource(String sourcePackageId, String sourceAggregateRunId);
}