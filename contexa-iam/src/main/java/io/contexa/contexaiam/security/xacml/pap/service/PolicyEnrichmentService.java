package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
public class PolicyEnrichmentService {

    private final PolicyTranslator policyTranslator;

    
    public void enrichPolicyWithFriendlyDescription(Policy policy) {
       

        if (policy == null) {
            return;
        }
        
        String description = policyTranslator.translatePolicyToString(policy);
        policy.setFriendlyDescription(description);
    }
}
