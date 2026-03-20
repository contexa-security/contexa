package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Collection;
import java.util.List;

public interface PermissionCatalogService {

    Permission synchronizePermissionFor(ManagedResource definedResource);

    List<PermissionDto> getAvailablePermissions();

    Page<PermissionDto> searchAvailablePermissions(String keyword, Collection<Long> excludeIds, Pageable pageable);
}