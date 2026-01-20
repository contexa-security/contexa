package io.contexa.contexaiam.domain.dto;

import lombok.Data;


@Data
public class ResourceMetadataDto {
    private String friendlyName;
    private String description;
    private String serviceOwner;
    private boolean isManaged;
}
