package io.contexa.contexaiam.admin.web.workflow.orchestrator.service;

import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowRequest;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowResult;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class WorkflowOrchestratorImpl implements WorkflowOrchestrator {

    private final PermissionWizardService permissionWizardService;

    
    @Override
    @Transactional
    public WorkflowResult executePermissionGrantWorkflow(WorkflowRequest request) {
        log.info("Executing permission grant workflow for roles: {}", request.getSelectedRoleIds());

        
        
        WizardContext context = permissionWizardService.beginCreation(
                request.getInitialRequest(),
                request.getPolicyName(),
                request.getPolicyDescription()
        );
        String contextId = context.contextId();
        log.info("Workflow context created with ID: {}", contextId);

        
        
        permissionWizardService.commitPolicy(
                contextId,
                request.getSelectedRoleIds(),
                request.getInitialRequest().getPermissionIds() 
        );
        log.info("Workflow completed. Role-permission assignments have been committed.");

        
        
        return new WorkflowResult(contextId, "SUCCESS", null);
    }
}