package io.contexa.contexaiam.admin.web.workflow.orchestrator.service;

import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowRequest;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowResult;

public interface WorkflowOrchestrator {
    
    WorkflowResult executePermissionGrantWorkflow(WorkflowRequest request);
}

