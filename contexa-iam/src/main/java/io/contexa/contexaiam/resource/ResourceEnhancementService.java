package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Slf4j
@RequiredArgsConstructor
public class ResourceEnhancementService {

    private final ResourceRegistryService resourceRegistryService;

    
    @Transactional
    public void defineResource(Long id, ResourceMetadataDto metadataDto) {
        log.info("Delegating resource definition for ID: {}", id);
        resourceRegistryService.defineResourceAsPermission(id, metadataDto);
    }

    
    @Transactional
    public void batchUpdateStatus(List<Long> ids, ManagedResource.Status status) {
        log.info("Batch updating status for {} resources to {}", ids.size(), status);
        
        
    }


    
    public void refreshResources() {
        log.info("Delegating resource refresh command.");
        resourceRegistryService.refreshAndSynchronizeResources();
    }
}
