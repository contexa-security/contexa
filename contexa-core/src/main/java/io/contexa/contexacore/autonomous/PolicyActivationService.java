package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.ActivationResult;


public interface PolicyActivationService {

    
    ActivationResult activatePolicy(Long proposalId, String approvedBy);

    
    boolean deactivatePolicy(Long proposalId, String deactivatedBy, String reason);
}
