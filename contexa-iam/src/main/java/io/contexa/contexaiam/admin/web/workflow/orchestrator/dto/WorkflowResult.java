package io.contexa.contexaiam.admin.web.workflow.orchestrator.dto;

public record WorkflowResult(
        String workflowId,
        String status, 
        Long createdPolicyId 
) {}