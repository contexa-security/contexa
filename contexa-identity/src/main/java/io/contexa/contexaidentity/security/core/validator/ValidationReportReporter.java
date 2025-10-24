package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidationReportReporter {

    private static final String BORDER_LINE = "=========================================================================================";
    private static final String ERROR_TITLE = "[ !!! DSL 보안 설정 유효성 검사 오류 !!! ]";
    private static final String WARNING_TITLE = "[ !!! DSL 보안 설정 유효성 검사 경고 !!! ]";
    private static final String INFO_TITLE = "[ DSL 보안 설정 유효성 검사 완료 ]";

    private static final String ERROR_PREFIX = "  [오류] ";
    private static final String WARNING_PREFIX = "  [경고] ";
    private static final String FIX_PREFIX = "    >> 제안: ";

    /**
     * ValidationResult를 기반으로 콘솔에 보고서를 출력합니다.
     * 오류가 있을 경우 DslConfigurationException을 발생시켜 서버 기동을 중단합니다.
     * @param result 검증 결과
     * @param dslSourceName DSL 설정 출처 (예: "PlatformSecurityConfig.java")
     * @throws DslConfigurationException 치명적인 오류가 있을 경우
     */
    public static void reportAndPotentiallyExit(ValidationResult result, String dslSourceName) throws DslConfigurationException {
        if (result == null) {
            log.error("ValidationResult is null. Cannot report validation status for DSL source: {}", dslSourceName);
            throw new DslConfigurationException("DSL 유효성 검사 중 내부 오류 발생: ValidationResult가 null입니다.");
        }

        StringBuilder reportBuilder = new StringBuilder("\n\n");
        reportBuilder.append(BORDER_LINE).append("\n");

        boolean hasErrors = result.hasErrors();
        boolean hasWarnings = result.hasWarnings();

        if (hasErrors) {
            reportBuilder.append(String.format("%s (설정 파일: %s)\n", ERROR_TITLE, dslSourceName));
            reportBuilder.append("-----------------------------------------------------------------------------------------\n");
            reportBuilder.append("  다음과 같은 설정 오류가 발견되었습니다:\n");
            reportBuilder.append(BORDER_LINE).append("\n\n");
            for (int i = 0; i < result.getErrors().size(); i++) {
                reportBuilder.append(ERROR_PREFIX).append(i + 1).append(". ").append(result.getErrors().get(i)).append("\n");
            }
        } else if (hasWarnings) {
            reportBuilder.append(String.format("%s (설정 파일: %s)\n", WARNING_TITLE, dslSourceName));
            reportBuilder.append("-----------------------------------------------------------------------------------------\n");
            reportBuilder.append("  다음과 같은 설정 경고가 발견되었습니다.:\n\n");
            for (int i = 0; i < result.getWarnings().size(); i++) {
                reportBuilder.append(WARNING_PREFIX).append(i + 1).append(". ").append(result.getWarnings().get(i)).append("\n");
            }
        } else {
            reportBuilder.append(String.format("%s (설정 파일: %s)\n", INFO_TITLE, dslSourceName));
            reportBuilder.append("-----------------------------------------------------------------------------------------\n");
            reportBuilder.append("  모든 DSL 보안 설정이 유효합니다.\n");
        }

        reportBuilder.append(BORDER_LINE).append("\n");

        if (hasErrors) {
            log.error(reportBuilder.toString());
            throw new DslConfigurationException("DSL 설정 유효성 검사 실패. 상세 내용은 로그를 확인하십시오. (Source: " + dslSourceName + ")");
        } else if (hasWarnings) {
            log.warn(reportBuilder.toString());
        } else {
            log.info(reportBuilder.toString());
        }
    }
}

