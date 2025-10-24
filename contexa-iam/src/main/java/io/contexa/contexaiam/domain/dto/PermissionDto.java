package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionDto {
    private Long id;
    private String name;
    private String friendlyName;
    private String description;
    private String targetType;
    private String actionType;
    private String conditionExpression;

    private Long managedResourceId;
    private String managedResourceIdentifier;
}