package io.contexa.contexaiam.aiam.protocol.request;

import java.util.List;

public record PolicyGenerationItem(
    String naturalLanguageQuery,
    AvailableItems availableItems) {
    
    public record AvailableItems(
        List<RoleItem> roles,
        List<PermissionItem> permissions,
        List<ConditionItem> conditions) {}
    
    public record RoleItem(
        Long id,
        String name,
        String description) {}
    
    public record PermissionItem(
        Long id,
        String name,
        String description,
        String targetType,
        String resourceIdentifier,
        String httpMethod) {}
    
    public record ConditionItem(
        Long id,
        String name,
        String description,
        Boolean isCompatible) {}
} 