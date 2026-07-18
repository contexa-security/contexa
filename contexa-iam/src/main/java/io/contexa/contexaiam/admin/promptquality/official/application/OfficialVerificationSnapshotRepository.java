package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;

import java.util.List;
import java.util.Optional;

public interface OfficialVerificationSnapshotRepository {

    Optional<OperatorRunBatch> findCurrentBatch(
            String packageId,
            String aggregateRunId,
            String diagnosticCatalogVersion);

    List<OperatorRunBatch> findRecentCurrentBatches(String diagnosticCatalogVersion, int limit);

}