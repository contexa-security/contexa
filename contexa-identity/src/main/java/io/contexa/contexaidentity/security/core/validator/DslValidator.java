package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import lombok.RequiredArgsConstructor;
import org.springframework.util.CollectionUtils;

import java.util.List;

@RequiredArgsConstructor
public class DslValidator implements Validator<PlatformConfig> {

    // PlatformConfig 전체를 대상으로 하는 Validator (예: 글로벌 설정 검증 - 현재는 해당 Validator 없음)
    private final List<Validator<PlatformConfig>> platformConfigValidators;

    // List<AuthenticationFlowConfig> 전체를 대상으로 하는 Validator (예: URL 중복 검사, MFA 플로우 간 중복 검사)
    private final List<Validator<List<AuthenticationFlowConfig>>> flowListValidators;

    // 개별 AuthenticationFlowConfig를 대상으로 하는 Validator (예: MFA 구조 검사, 광범위한 RequestMatcher 검사)
    private final List<Validator<AuthenticationFlowConfig>> singleFlowValidators;

    // 개별 AuthenticationStepConfig를 대상으로 하는 Validator (예: 필수 옵션, Feature 가용성, 커스텀 Bean 의존성 검사)
    private final List<Validator<AuthenticationStepConfig>> stepValidators;


    @Override
    public ValidationResult validate(PlatformConfig platformConfig) {
        ValidationResult finalResult = new ValidationResult();

        if (platformConfig == null) {
            finalResult.addError("PlatformConfig가 null 입니다. DSL 설정을 검증할 수 없습니다.");
            return finalResult;
        }

        List<FlowContext> flowContexts = platformConfig.getPlatformContext().flowContexts();


        // 1. PlatformConfig 전체 수준 검증
        if (!CollectionUtils.isEmpty(platformConfigValidators)) {
            for (Validator<PlatformConfig> pv : platformConfigValidators) {
                finalResult.merge(pv.validate(platformConfig));
            }
        }

        List<AuthenticationFlowConfig> flows = platformConfig.getFlows();

        // 2. Flow 목록 전체 수준 검증 (예: URL 중복 검사)
        // 이 Validator 들은 PlatformConfig 에서 flows를 직접 가져와서 사용하거나,
        // DslValidator가 flows를 명시적으로 전달해야 함.
        // 현재는 Validator<List<AuthenticationFlowConfig>> 타입이므로 flows를 직접 전달.
        if (!CollectionUtils.isEmpty(flowListValidators)) {
            for (Validator<List<AuthenticationFlowConfig>> flv : flowListValidators) {
                finalResult.merge(flv.validate(flows));
            }
        }

        // 3. 개별 Flow 및 그 하위 Step 검증
        if (!CollectionUtils.isEmpty(flows)) {
            for (AuthenticationFlowConfig flow : flows) {
                // 개별 Flow 수준 검증
                if (!CollectionUtils.isEmpty(singleFlowValidators)) {
                    for (Validator<AuthenticationFlowConfig> sfv : singleFlowValidators) {
                        finalResult.merge(sfv.validate(flow));
                    }
                }
                // 개별 Step 수준 검증
                if (!CollectionUtils.isEmpty(stepValidators) && !CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                        for (Validator<AuthenticationStepConfig> sv : stepValidators) {
                            finalResult.merge(sv.validate(step));
                        }
                    }
                }
            }
        }
        return finalResult;
    }
}

