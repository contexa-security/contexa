package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates that all AuthenticationFlowConfig instances (both MFA and single authentication flows)
 * have unique typeNames (flow names) among the provided list of AuthenticationFlowConfig objects.
 * <p>
 * Duplicate typeNames (defined by .name() in DSL) can lead to incorrect flow resolution
 * and runtime ambiguity. The uniqueness of flow names is checked case-insensitively.
 * This validator is intended to be part of the {@link DslValidator}'s flowListValidators.
 */
public class DuplicateFlowTypeNameValidator implements Validator<List<AuthenticationFlowConfig>> { // 인터페이스 제네릭 변경

    private static final Logger log = LoggerFactory.getLogger(DuplicateFlowTypeNameValidator.class);

    @Override
    public ValidationResult validate(List<AuthenticationFlowConfig> allFlowConfigs) { // 파라미터 타입 변경
        ValidationResult result = new ValidationResult();

        if (CollectionUtils.isEmpty(allFlowConfigs)) {
            log.debug("No AuthenticationFlowConfigs provided to DuplicateFlowTypeNameValidator. Validation successful by default.");
            return result;
        }

        log.info("Starting validation for duplicate AuthenticationFlowConfig typeNames. Total flows configured: {}", allFlowConfigs.size());

        Set<String> uniqueNormalizedTypeNames = new HashSet<>();
        Set<String> duplicateOriginalTypeNames = new HashSet<>();

        for (AuthenticationFlowConfig flow : allFlowConfigs) {
            if (flow == null) {
                log.warn("A null AuthenticationFlowConfig object was found. Skipping this entry.");
                continue;
            }
            String typeName = flow.getTypeName(); // AuthenticationFlowConfig에 getTypeName()이 있다고 가정

            if (!StringUtils.hasText(typeName)) {
                String authType = flow.getTypeName() ;
                log.warn("An AuthenticationFlowConfig (AuthType: {}) was found with a null or empty typeName (flow name). " +
                                "This entry will be skipped for duplicate check, but it's a configuration issue that should be addressed.",
                        authType != null ? authType : "UNKNOWN");
                // typeName이 없는 경우, 오류로 처리할 수도 있습니다.
                // result.addError("An AuthenticationFlowConfig (AuthType: " + (authType != null ? authType.name() : "UNKNOWN") + ") has a missing typeName.");
                continue;
            }

            // Flow 이름의 고유성은 대소문자를 구분하지 않고 검사
            String normalizedTypeName = typeName.toLowerCase();

            if (!uniqueNormalizedTypeNames.add(normalizedTypeName)) {
                duplicateOriginalTypeNames.add(typeName); // 오류 보고를 위해 원본 typeName 기록
            }
        }

        if (!duplicateOriginalTypeNames.isEmpty()) {
            String duplicatesMessage = duplicateOriginalTypeNames.stream()
                    .distinct()
                    .map(name -> "'" + name + "'")
                    .collect(Collectors.joining(", "));
            String errorMessage = String.format(
                    "CRITICAL CONFIGURATION ERROR: Duplicate AuthenticationFlowConfig typeName(s) (flow name) found: %s. " +
                            "Each authentication flow (MFA or single, defined by .name() in your DSL, e.g., PlatformSecurityConfig) MUST have a unique name (case-insensitive for this check). " +
                            "Please review your security configuration to ensure all flow names are unique to prevent runtime ambiguity and errors.",
                    duplicatesMessage
            );
            log.error(errorMessage);
            result.addError(errorMessage); // ValidationResult에 오류 추가
        } else {
            log.info("Validation successful: All AuthenticationFlowConfig typeNames are unique (case-insensitive).");
        }
        return result;
    }

    // isConsideredAsMfaFlow 메소드는 더 이상 필요하지 않음 (모든 플로우를 대상으로 하므로)

    // DslValidatorService에서 순서 관리를 위해 @Order 애노테이션을 클래스 레벨에 사용하거나,
    // DslValidator 인터페이스가 Ordered를 상속하고 이 메소드를 구현하도록 할 수 있습니다.
    // 현재 DslValidator.java는 Ordered를 상속하지 않으므로, @Order 사용 또는 DslValidatorService의 정렬 로직에 의존.
    // public int getOrder() { return 110; } // 필요시 @Order(110) 등으로 대체
}