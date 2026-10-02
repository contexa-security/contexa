package io.contexa.demo.comparison.batch.source;

import io.contexa.demo.comparison.batch.dto.ArmBatchFingerprint;
import io.contexa.demo.comparison.batch.dto.ComparisonExportSelection;

public interface ComparisonBatchSource {

    ArmBatchFingerprint capture(String arm, ComparisonExportSelection selection);
}
