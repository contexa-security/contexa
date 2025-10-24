package io.contexa.contexaiam.admin.web.studio.service;

import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationRequestDto;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;

public interface StudioActionService {
    SimulationResultDto runPolicySimulation(SimulationRequestDto simulationRequest);
    WizardContext initiateGrantWorkflow(InitiateGrantRequestDto grantRequest);
}