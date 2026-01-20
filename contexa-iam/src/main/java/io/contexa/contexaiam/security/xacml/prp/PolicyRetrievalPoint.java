package io.contexa.contexaiam.security.xacml.prp;

import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.List;


public interface PolicyRetrievalPoint {

    
    List<Policy> findUrlPolicies();

    
    void clearUrlPoliciesCache();

    
    List<Policy> findMethodPolicies(String methodIdentifier);

    
    void clearMethodPoliciesCache();

    
    List<Policy> findMethodPolicies(String methodIdentifier, String phase);
}