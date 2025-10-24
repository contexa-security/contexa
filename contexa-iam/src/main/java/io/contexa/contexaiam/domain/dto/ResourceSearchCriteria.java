package io.contexa.contexaiam.domain.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import lombok.Data;

/**
 * 관리 리소스 검색 조건을 담는 DTO.
 */
@Data
public class ResourceSearchCriteria {
    private String keyword; // friendlyName, resourceIdentifier, serviceOwner 등에서 검색
    private ManagedResource.ResourceType resourceType; // URL 또는 METHOD
    private String serviceOwner;
    private ManagedResource.Status status;
}
