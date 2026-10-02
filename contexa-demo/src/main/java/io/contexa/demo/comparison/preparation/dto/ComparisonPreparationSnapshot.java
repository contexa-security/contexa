package io.contexa.demo.comparison.preparation.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.comparison.batch.dto.ArmBatchFingerprint;

import java.util.List;

public record ComparisonPreparationSnapshot(
        ComparisonRequestPlan requestPlan,
        List<ArmDocumentFingerprint> documents,
        boolean documentsMatch,
        ReadinessReport readiness,
        List<PreparationBlocker> blockers,
        boolean readyForExecution,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<ArmCustomerFingerprint> customers,
        @JsonInclude(JsonInclude.Include.NON_NULL) Boolean customersMatch,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<ArmBatchFingerprint> batches,
        @JsonInclude(JsonInclude.Include.NON_NULL) Boolean batchesMatch
) {

    @JsonIgnore
    public List<? extends ComparisonResourceFingerprint> resources() {
        return batches != null ? batches : customers == null ? documents : customers;
    }
}
