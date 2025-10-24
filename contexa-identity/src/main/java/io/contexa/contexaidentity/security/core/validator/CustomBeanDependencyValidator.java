package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

@Slf4j
@RequiredArgsConstructor
public class CustomBeanDependencyValidator implements Validator<AuthenticationStepConfig> {

    private final ApplicationContext applicationContext;

    @Override
    public ValidationResult validate(AuthenticationStepConfig step) {
        ValidationResult result = new ValidationResult();
        if (step == null || step.getOptions() == null) {
            return result;
        }

        String stepIdentifier = String.format("Step (type: '%s', order: %d)", step.getType(), step.getOrder());
        Object optionsObject = step.getOptions().get("_options");

        if (optionsObject instanceof AuthenticationProcessingOptions) {
            AuthenticationProcessingOptions processingOptions = (AuthenticationProcessingOptions) optionsObject;

            // 예시: AuthenticationProcessingOptions에 getSuccessHandlerBeanName() 같은 메서드가 있다고 가정
            // String customSuccessHandlerBeanName = processingOptions.getSuccessHandlerBeanName();
            // if (StringUtils.hasText(customSuccessHandlerBeanName) && !applicationContext.containsBean(customSuccessHandlerBeanName)) {
            //     result.addError(String.format("치명적 오류: %s에 명시적으로 설정된 커스텀 성공 핸들러 빈('%s')을 찾을 수 없습니다.", stepIdentifier, customSuccessHandlerBeanName));
            // }

            // 현재는 successHandler, failureHandler가 직접 객체로 설정됨.
            // 만약 문자열로 Bean 이름을 받도록 DSL을 확장한다면 위와 같은 검증 필요.
            // 현재 구조에서는 이 Validator가 크게 할 일이 없을 수 있으나, 예시로 남겨둠.

            // 실제 객체가 설정되었으나, 해당 타입의 빈이 Spring 컨텍스트에 없는 경우를 검사할 수도 있지만,
            // 이는 주입 시점에서 이미 오류가 발생하므로 중복 검사일 수 있음.
            // (예: PlatformSecurityConfig에서 핸들러들을 @Autowired로 주입받으므로, 없으면 거기서 오류 발생)

            // 하지만, 사용자가 DSL을 통해 new MyCustomHandler() 와 같이 직접 인스턴스를 생성해서 넘겼고,
            // 그 MyCustomHandler가 내부적으로 @Autowired 필드를 가지고 있는데 Spring 컨테이너의 관리를 받지 못해 주입 실패하는 경우는 여기서 잡기 어려움.
            // -> 이는 DSL 사용 가이드에서 Spring Bean을 사용하도록 권장해야 함.
        }

        return result;
    }
}