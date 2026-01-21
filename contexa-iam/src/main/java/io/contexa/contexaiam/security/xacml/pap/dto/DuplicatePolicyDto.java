package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record DuplicatePolicyDto(String reason, List<Long> policyIds, String policySignature) {}