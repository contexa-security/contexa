package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.dto.*;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;

import java.util.List;


public interface PolicyBuilderService {
    
    List<PolicyTemplateDto> getAvailableTemplates(PolicyContext context);

    
    Policy buildPolicyFromVisualComponents(VisualPolicyDto visualPolicyDto);

    
    SimulationResultDto simulatePolicy(Policy policyToSimulate, SimulationContext context);

    
    List<PolicyConflictDto> detectConflicts(Policy newPolicy);
}