package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.dto.*;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;

import java.util.List;

/**
 * 비전문가 사용자를 위한 시각적 정책 빌더 및 시뮬레이션 기능을 제공하는 서비스입니다.
 */
public interface PolicyBuilderService {
    /**
     * 일반적인 시나리오에 맞는 사전 정의된 정책 템플릿 목록을 제공합니다.
     */
    List<PolicyTemplateDto> getAvailableTemplates(PolicyContext context);

    /**
     * 시각적 빌더 UI로부터 전달받은 구성 요소를 실제 Policy 객체로 변환합니다.
     */
    Policy buildPolicyFromVisualComponents(VisualPolicyDto visualPolicyDto);

    /**
     * 새로 생성하거나 수정한 정책이 실제 운영 환경에 어떤 영향을 미칠지 미리 시뮬레이션합니다.
     */
    SimulationResultDto simulatePolicy(Policy policyToSimulate, SimulationContext context);

    /**
     * 새로운 정책이 기존 정책들과 충돌하는지 감지합니다.
     */
    List<PolicyConflictDto> detectConflicts(Policy newPolicy);
}