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

    private final List<Validator<PlatformConfig>> platformConfigValidators;

    private final List<Validator<List<AuthenticationFlowConfig>>> flowListValidators;

    private final List<Validator<AuthenticationFlowConfig>> singleFlowValidators;

    private final List<Validator<AuthenticationStepConfig>> stepValidators;

    @Override
    public ValidationResult validate(PlatformConfig platformConfig) {
        ValidationResult finalResult = new ValidationResult();

        if (platformConfig == null) {
            finalResult.addError("PlatformConfig가 null 입니다. DSL 설정을 검증할 수 없습니다.");
            return finalResult;
        }

        List<FlowContext> flowContexts = platformConfig.getPlatformContext().flowContexts();

        if (!CollectionUtils.isEmpty(platformConfigValidators)) {
            for (Validator<PlatformConfig> pv : platformConfigValidators) {
                finalResult.merge(pv.validate(platformConfig));
            }
        }

        List<AuthenticationFlowConfig> flows = platformConfig.getFlows();

        if (!CollectionUtils.isEmpty(flowListValidators)) {
            for (Validator<List<AuthenticationFlowConfig>> flv : flowListValidators) {
                finalResult.merge(flv.validate(flows));
            }
        }

        if (!CollectionUtils.isEmpty(flows)) {
            for (AuthenticationFlowConfig flow : flows) {
                
                if (!CollectionUtils.isEmpty(singleFlowValidators)) {
                    for (Validator<AuthenticationFlowConfig> sfv : singleFlowValidators) {
                        finalResult.merge(sfv.validate(flow));
                    }
                }
                
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

