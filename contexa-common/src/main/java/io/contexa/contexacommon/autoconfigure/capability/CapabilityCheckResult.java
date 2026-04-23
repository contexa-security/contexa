package io.contexa.contexacommon.autoconfigure.capability;

import java.util.List;

public record CapabilityCheckResult(
        ContexaCapability capability,
        CapabilityStatus status,
        boolean required,
        String reason,
        List<String> presentBeans,
        List<String> missingBeans,
        List<String> recommendations) {

    public CapabilityCheckResult {
        presentBeans = List.copyOf(presentBeans == null ? List.of() : presentBeans);
        missingBeans = List.copyOf(missingBeans == null ? List.of() : missingBeans);
        recommendations = List.copyOf(recommendations == null ? List.of() : recommendations);
    }

    public boolean shouldFail(CapabilityMode mode) {
        if (!required || mode == CapabilityMode.OFF || mode == CapabilityMode.WARN) {
            return false;
        }
        return status == CapabilityStatus.INACTIVE_UNEXPECTED || status == CapabilityStatus.FAILED;
    }
}
