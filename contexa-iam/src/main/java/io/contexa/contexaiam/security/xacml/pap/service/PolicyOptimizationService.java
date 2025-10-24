package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;

import java.util.List;

public interface PolicyOptimizationService {
    List<DuplicatePolicyDto> findDuplicatePolicies();
    PolicyDto proposeMerge(List<Long> policyIds);
}