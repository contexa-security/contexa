package io.contexa.demo.comparison.preparation.source;

import io.contexa.demo.comparison.preparation.dto.ArmCustomerFingerprint;

public interface ComparisonCustomerSource {

    ArmCustomerFingerprint capture(String customerId);
}
