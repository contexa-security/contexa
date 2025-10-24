package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DslValidatorService {

    private final DslValidator dslValidator; // 통합 Validator 하나만 주입

    /**
     * 제공된 PlatformConfig에 대해 DSL 유효성 검사를 수행합니다.
     * 오류 발견 시 콘솔에 보고하고 DslConfigurationException을 발생시켜 기동을 중단합니다.
     *
     * @param platformConfig 검증할 플랫폼 설정 객체
     * @param dslSourceName  설정 소스 이름 (예: "PlatformSecurityConfig.java")
     * @throws DslConfigurationException 유효성 검사 실패 시
     */
    public void validate(PlatformConfig platformConfig, String dslSourceName) throws DslConfigurationException {
        if (platformConfig == null) {
            // ValidationReportReporter가 예외를 던지도록 수정되었으므로, 여기서 직접 예외를 던질 필요 없음.
            ValidationResult nullConfigResult = new ValidationResult();
            nullConfigResult.addError("PlatformConfig가 null입니다. DSL 설정을 로드할 수 없습니다.");
            ValidationReportReporter.reportAndPotentiallyExit(nullConfigResult, dslSourceName);
            return; // 위에서 예외 발생으로 실제로는 도달하지 않음
        }

        ValidationResult result = dslValidator.validate(platformConfig); // 통합 Validator 호출
        ValidationReportReporter.reportAndPotentiallyExit(result, dslSourceName);
    }
}
