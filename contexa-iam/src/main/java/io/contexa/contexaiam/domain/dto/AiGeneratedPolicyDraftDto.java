package io.contexa.contexaiam.domain.dto;

import java.util.Map;

public record AiGeneratedPolicyDraftDto(
        BusinessPolicyDto policyData,
        Map<String, String> roleIdToNameMap,
        Map<String, String> permissionIdToNameMap,
        Map<String, String> conditionIdToNameMap
) {}