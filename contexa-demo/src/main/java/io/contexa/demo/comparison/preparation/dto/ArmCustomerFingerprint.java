package io.contexa.demo.comparison.preparation.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.demo.work.shared.dto.WorkText;

public record ArmCustomerFingerprint(
        String arm,
        String state,
        String customerId,
        Integer version,
        String projectId,
        String customerSha256,
        WorkText name
) implements ComparisonResourceFingerprint {

    @Override
    @JsonIgnore
    public String resourceId() {
        return customerId;
    }

    @Override
    @JsonIgnore
    public String sourceSha256() {
        return customerSha256;
    }
}
