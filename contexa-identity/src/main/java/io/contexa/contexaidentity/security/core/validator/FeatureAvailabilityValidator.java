package io.contexa.contexaidentity.security.core.validator;


import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class FeatureAvailabilityValidator implements Validator<AuthenticationStepConfig> {

    private final AdapterRegistry adapterRegistry;

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getType() == null) {
            result.addError("치명적 오류: 인증 스텝 또는 스텝 타입이 null입니다. DSL 설정을 확인하십시오.");
            return result;
        }

        String stepType = step.getType().toLowerCase();
        if (adapterRegistry.getAuthenticationAdapter(stepType) == null) {
            result.addError(String.format("치명적 플랫폼 오류: DSL에 정의된 인증 방식 '%s'(을)를 처리할 수 있는 AuthenticationFeature 구현체가 FeatureRegistry에 등록되지 않았습니다. (Step order: %d)",
                    step.getType(), step.getOrder()));
            log.error("DSL VALIDATION ERROR: AuthenticationFeature not found for type '{}'", step.getType());
        }
        return result;
    }
}
