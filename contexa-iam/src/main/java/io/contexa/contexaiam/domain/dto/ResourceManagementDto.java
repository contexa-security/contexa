package io.contexa.contexaiam.domain.dto;

import io.contexa.contexacommon.entity.ManagedResource;
import lombok.Data;


@Data
public class ResourceManagementDto {
    private ManagedResource.Status status;
}