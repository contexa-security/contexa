package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;

import java.util.List;

@Slf4j
public class MfaFlowStructureValidator implements Validator<AuthenticationFlowConfig> {

    @Override
    public ValidationResult validate(AuthenticationFlowConfig flow) {
        ValidationResult result = new ValidationResult();
        if (flow == null || !"mfa".equalsIgnoreCase(flow.getTypeName())) {
            return result;
        }

        String flowIdentifier = String.format("MFA Flow (type: '%s', order: %d)", flow.getTypeName(), flow.getOrder());

        List<AuthenticationStepConfig> steps = flow.getStepConfigs();
        if (CollectionUtils.isEmpty(steps)) {
            result.addError(String.format("치명적 오류: %s에 정의된 인증 단계(stepConfigs)가 없습니다. MFA 플로우는 1차 인증과 최소 1개의 2차 인증 요소를 포함해야 합니다.", flowIdentifier));
            return result;
        }

        // 1. 1차 인증 검사
        AuthenticationStepConfig firstStep = steps.get(0);
        if (firstStep.getOrder() != 0 ||
                ! ("form".equalsIgnoreCase(firstStep.getType()) || "mfa_rest".equalsIgnoreCase(firstStep.getType())) ) {
            result.addError(String.format("치명적 오류: %s의 첫 번째 인증 단계는 'form' 또는 'rest' 방식이어야 하며, order는 0이어야 합니다. 현재: type='%s', order=%d",
                    flowIdentifier, firstStep.getType(), firstStep.getOrder()));
        }

        // 2. 최소 2개 스텝 (1차 인증 + 1개 이상의 2차 인증 요소) 검사
        if (steps.size() < 2) {
            result.addError(String.format("치명적 오류: %s에는 1차 인증 외에 최소 1개 이상의 2차 인증 요소가 필요합니다. 현재 총 스텝 수: %d",
                    flowIdentifier, steps.size()));
        }

        if (result.hasErrors()){
            log.error("DSL VALIDATION ERROR for {}: {}", flowIdentifier, result.getErrors());
        }
        return result;
    }
}
