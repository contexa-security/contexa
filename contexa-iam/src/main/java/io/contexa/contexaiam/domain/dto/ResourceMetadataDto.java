package io.contexa.contexaiam.domain.dto;

import lombok.Data;

/**
 * 리소스 메타데이터 업데이트 요청을 위한 DTO.
 */
@Data
public class ResourceMetadataDto {
    private String friendlyName;
    private String description;
    private String serviceOwner;
    private boolean isManaged;
}
