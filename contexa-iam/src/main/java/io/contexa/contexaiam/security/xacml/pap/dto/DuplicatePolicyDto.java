package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature,
                                  DuplicateType type) {

    public enum DuplicateType {
        EXACT,
        SEMANTIC,
        SUBSET,
        HIERARCHY_SUBSUME
    }

    public DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature) {
        this(reason, policyIds, policySignature, DuplicateType.EXACT);
    }
}