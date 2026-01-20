package io.contexa.contexaiam.domain.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import lombok.Data;


@Data
public class ResourceSearchCriteria {
    private String keyword; 
    private ManagedResource.ResourceType resourceType; 
    private String serviceOwner;
    private ManagedResource.Status status;
}
