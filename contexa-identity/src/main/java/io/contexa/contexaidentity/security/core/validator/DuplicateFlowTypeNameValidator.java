package io.contexa.contexaidentity.security.core.validator;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class DuplicateFlowTypeNameValidator implements Validator<List<AuthenticationFlowConfig>> {

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
                log.error("A null AuthenticationFlowConfig object was found. Skipping this entry.");
                continue;
            }
            String typeName = flow.getTypeName();

            if (!StringUtils.hasText(typeName)) {
                log.error("An AuthenticationFlowConfig was found with a null or empty typeName. This is a configuration issue.");
                continue;
            }

            String normalizedTypeName = typeName.toLowerCase();

            if (!uniqueNormalizedTypeNames.add(normalizedTypeName)) {
                duplicateOriginalTypeNames.add(typeName);
            }
        }

        if (!duplicateOriginalTypeNames.isEmpty()) {
            String duplicatesMessage = duplicateOriginalTypeNames.stream()
                    .map(name -> "'" + name + "'")
                    .collect(Collectors.joining(", "));
            String errorMessage = String.format(
                    "Duplicate flow typeName(s) found: %s. Each authentication flow must have a unique name (case-insensitive).",
                    duplicatesMessage
            );
            log.error(errorMessage);
            result.addError(errorMessage);
        }
        return result;
    }
}
