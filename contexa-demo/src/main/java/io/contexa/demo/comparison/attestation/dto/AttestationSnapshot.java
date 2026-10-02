package io.contexa.demo.comparison.attestation.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.demo.comparison.preparation.dto.ArmCustomerFingerprint;
import io.contexa.demo.comparison.preparation.dto.ComparisonResourceFingerprint;
import io.contexa.demo.identity.dto.IdentityView;
import io.contexa.demo.comparison.preparation.dto.ArmDocumentFingerprint;
import io.contexa.demo.readiness.dto.RuntimeMode;
import io.contexa.demo.comparison.batch.dto.ArmBatchFingerprint;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import java.util.List;

public record AttestationSnapshot(
        IdentityView identity,
        String sessionSha256,
        ArmDocumentFingerprint document,
        List<String> assignedProjects,
        RuntimeMode runtimeMode,
        ExecutionEnvironment environment,
        HistoryFingerprint history,
        LoginOrigin loginOrigin,
        @JsonInclude(JsonInclude.Include.NON_NULL) ArmCustomerFingerprint customer,
        @JsonInclude(JsonInclude.Include.NON_NULL) ArmBatchFingerprint batch,
        @JsonInclude(JsonInclude.Include.NON_NULL) ApprovalEvidence approval
) {

    @JsonIgnore
    public ComparisonResourceFingerprint resource() {
        return batch != null ? batch : customer == null ? document : customer;
    }
}
