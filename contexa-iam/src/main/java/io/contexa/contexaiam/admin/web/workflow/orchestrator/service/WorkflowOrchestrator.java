package io.contexa.contexaiam.admin.web.workflow.orchestrator.service;

import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowRequest;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowResult;

/**
 * 복잡한 비즈니스 워크플로우를 조정(Orchestrate)하는 최상위 서비스입니다.
 */
public interface WorkflowOrchestrator {
    /**
     * '권한 부여' 전체 워크플로우를 시작부터 끝까지 실행합니다.
     * @param request 권한 부여 요청에 필요한 모든 초기 데이터
     * @return 워크플로우 실행 결과
     */
    WorkflowResult executePermissionGrantWorkflow(WorkflowRequest request);
}

