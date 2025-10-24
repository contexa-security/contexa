package io.contexa.contexaiam.admin.web.workflow.orchestrator.service;

import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowRequest;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.dto.WorkflowResult;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class WorkflowOrchestratorImpl implements WorkflowOrchestrator {

    private final PermissionWizardService permissionWizardService;

    /**
     * [최종 수정] RBAC 중심의 아키텍처에 맞춰 워크플로우를 재설계합니다.
     * 이 메서드는 이제 특정 권한을 여러 역할에 할당하는 전체 과정을 실행합니다.
     */
    @Override
    @Transactional
    public WorkflowResult executePermissionGrantWorkflow(WorkflowRequest request) {
        log.info("Executing permission grant workflow for roles: {}", request.getSelectedRoleIds());

        // 1. 마법사 워크플로우 시작 및 컨텍스트 생성
        // beginCreation은 이제 생성된 WizardContext 객체를 반환합니다.
        WizardContext context = permissionWizardService.beginCreation(
                request.getInitialRequest(),
                request.getPolicyName(),
                request.getPolicyDescription()
        );
        String contextId = context.contextId();
        log.info("Workflow context created with ID: {}", contextId);

        // 2. 워크플로우 실행: 생성된 컨텍스트와 요청에 담긴 역할 ID들을 사용하여
        //    Permission-Role 관계를 설정합니다.
        permissionWizardService.commitPolicy(
                contextId,
                request.getSelectedRoleIds(),
                request.getInitialRequest().getPermissionIds() // request 객체에서 permissionIds를 가져와 전달
        );
        log.info("Workflow completed. Role-permission assignments have been committed.");

        // 3. 결과 반환
        // 이 워크플로우는 더 이상 특정 단일 정책을 생성하지 않으므로, policyId는 null을 반환합니다.
        return new WorkflowResult(contextId, "SUCCESS", null);
    }
}