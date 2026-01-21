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

public class DuplicateFlowTypeNameValidator implements Validator<List<AuthenticationFlowConfig>> { 

    private static final Logger log = LoggerFactory.getLogger(DuplicateFlowTypeNameValidator.class);

    @Override
    public ValidationResult validate(List<AuthenticationFlowConfig> allFlowConfigs) { 
        ValidationResult result = new ValidationResult();

        if (CollectionUtils.isEmpty(allFlowConfigs)) {
                        return result;
        }

        Set<String> uniqueNormalizedTypeNames = new HashSet<>();
        Set<String> duplicateOriginalTypeNames = new HashSet<>();

        for (AuthenticationFlowConfig flow : allFlowConfigs) {
            if (flow == null) {
                log.warn("A null AuthenticationFlowConfig object was found. Skipping this entry.");
                continue;
            }
            String typeName = flow.getTypeName(); 

            if (!StringUtils.hasText(typeName)) {
                String authType = flow.getTypeName() ;
                log.warn("An AuthenticationFlowConfig (AuthType: {}) was found with a null or empty typeName (flow name). " +
                                "This entry will be skipped for duplicate check, but it's a configuration issue that should be addressed.",
                        authType != null ? authType : "UNKNOWN");

                continue;
            }

            String normalizedTypeName = typeName.toLowerCase();

            if (!uniqueNormalizedTypeNames.add(normalizedTypeName)) {
                duplicateOriginalTypeNames.add(typeName); 
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
            result.addError(errorMessage); 
        } else {
                    }
        return result;
    }

}