package io.contexa.contexaiam.admin.support.translation;

import io.contexa.contexaiam.domain.entity.policy.Policy;


public interface TerminologyTranslationService {
    
    String generatePermissionDescription(String permissionName);

    
    String summarizePolicy(Policy policy);
}
