package io.contexa.contexaiam.domain.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import lombok.Data;

@Data
public class ManagedResourceDto {
    private Long id;
    private String resourceIdentifier;
    private ManagedResource.ResourceType resourceType;
    private String friendlyName;
    private String description;
    private String serviceOwner;
    private String parameterTypes;
    private String returnType;
    private boolean isManaged;
    private Long permissionId;
    private String permissionName;
}
