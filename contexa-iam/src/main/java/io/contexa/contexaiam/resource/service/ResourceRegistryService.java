package io.contexa.contexaiam.resource.service;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Set;

public interface ResourceRegistryService {
    
    void refreshAndSynchronizeResources();

    Permission defineResourceAsPermission(Long resourceId, ResourceMetadataDto metadataDto);

    Page<ManagedResource> findResources(ResourceSearchCriteria searchCriteria, Pageable pageable);

    void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto); 

    void excludeResourceFromManagement(Long resourceId);

    void restoreResourceToManagement(Long resourceId);

    Set<String> getAllServiceOwners();
    void batchUpdateStatus(List<Long> ids, ManagedResource.Status status);
}