package io.contexa.contexaiam.admin.web.workflow.wizard.service;

import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.admin.web.studio.dto.WizardInitiationDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.AssignmentChangeDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.InitiateManagementRequestDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;

public interface GrantingWizardService {

    
    WizardInitiationDto beginManagementSession(InitiateManagementRequestDto request);

    
    WizardContext getWizardProgress(String contextId);

    
    SimulationResultDto simulateAssignmentChanges(String contextId, AssignmentChangeDto changes);

    
    void commitAssignments(String contextId, AssignmentChangeDto finalAssignments);
}
