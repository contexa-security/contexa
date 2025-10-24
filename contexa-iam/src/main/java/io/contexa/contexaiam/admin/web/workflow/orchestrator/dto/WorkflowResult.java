package io.contexa.contexaiam.admin.web.workflow.orchestrator.dto;

/**
 * 워크플로우 실행 결과를 담는 DTO 입니다.
 */
public record WorkflowResult(
        String workflowId,
        String status, // "SUCCESS", "FAILURE"
        Long createdPolicyId // [수정] RBAC 중심에서는 null일 수 있음
) {}