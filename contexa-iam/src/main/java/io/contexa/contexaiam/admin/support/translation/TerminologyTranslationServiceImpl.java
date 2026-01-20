package io.contexa.contexaiam.admin.support.translation;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class TerminologyTranslationServiceImpl implements TerminologyTranslationService {

    private final PermissionRepository permissionRepository;
    private final PolicyTranslator policyTranslator;

    
    @Override
    public String generatePermissionDescription(String permissionName) {
        return permissionRepository.findByName(permissionName)
                .map(p -> p.getDescription())
                .orElse(permissionName);
    }

    
    @Override
    public String summarizePolicy(Policy policy) {
        if (policy.getFriendlyDescription() != null && !policy.getFriendlyDescription().isEmpty()) {
            return policy.getFriendlyDescription();
        }
        
        return policyTranslator.parsePolicy(policy).getConditionDescription();
    }
}