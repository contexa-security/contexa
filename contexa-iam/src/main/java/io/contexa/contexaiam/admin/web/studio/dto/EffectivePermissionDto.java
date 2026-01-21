package io.contexa.contexaiam.admin.web.studio.dto;

public record EffectivePermissionDto(
        String permissionName,
        String permissionDescription,
        String origin 
) {}