package io.contexa.contexaiam.admin.web.workflow.wizard.service;

import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.admin.web.studio.dto.WizardInitiationDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.AssignmentChangeDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.InitiateManagementRequestDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;

public interface GrantingWizardService {

    /**
     * 주체에 대한 멤버십 '관리' 세션을 시작합니다.
     * WizardContext를 생성하고 관리 대상 주체와 현재 멤버십 정보를 저장합니다.
     * @param request 관리 대상 주체 정보
     * @return 마법사 UI로 리다이렉트하기 위한 정보
     */
    WizardInitiationDto beginManagementSession(InitiateManagementRequestDto request);

    /**
     * 현재 마법사 진행 상태(컨텍스트)를 조회합니다.
     * @param contextId 관리 세션 ID
     * @return 현재 상태가 담긴 WizardContext
     */
    WizardContext getWizardProgress(String contextId);

    /**
     * [신규 메서드]
     * UI에서 발생한 임시 할당 변경사항을 기반으로 최종 권한을 시뮬레이션합니다.
     * 이 메서드는 DB에 어떤 변경도 가하지 않습니다(read-only).
     *
     * @param contextId 현재 관리 세션 ID
     * @param changes   UI에서 변경된 할당 정보
     * @return 최종 유효 권한 목록, SoD 위반 경고 등을 포함한 분석 결과
     */
    SimulationResultDto simulateAssignmentChanges(String contextId, AssignmentChangeDto changes);

    /**
     * 최종 확정된 멤버십 할당 정보를 DB에 저장합니다.
     * User/Group의 멤버십을 실제로 변경합니다.
     * @param finalAssignments 최종 확정된 모든 할당 정보
     */
    void commitAssignments(String contextId, AssignmentChangeDto finalAssignments);
}
