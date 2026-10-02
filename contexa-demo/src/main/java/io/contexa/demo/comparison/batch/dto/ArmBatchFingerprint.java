package io.contexa.demo.comparison.batch.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.demo.comparison.preparation.dto.ComparisonResourceFingerprint;
import io.contexa.demo.work.export.dto.ExportResourceType;
import java.util.List;

public record ArmBatchFingerprint(String arm, String state, ExportResourceType resourceType,
        List<BatchFingerprintItem> items, String batchSha256) implements ComparisonResourceFingerprint {

    @Override
    @JsonIgnore
    public String resourceId() {
        return batchSha256;
    }

    @Override
    @JsonIgnore
    public String sourceSha256() {
        return batchSha256;
    }
}
