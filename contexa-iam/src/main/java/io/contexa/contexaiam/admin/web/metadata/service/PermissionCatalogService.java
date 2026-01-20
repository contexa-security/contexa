package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;

import java.util.List;


public interface PermissionCatalogService {

    
    Permission synchronizePermissionFor(ManagedResource definedResource);

    
    List<PermissionDto> getAvailablePermissions();
}