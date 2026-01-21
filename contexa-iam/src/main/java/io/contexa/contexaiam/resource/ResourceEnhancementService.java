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
                resourceRegistryService.defineResourceAsPermission(id, metadataDto);
    }

    @Transactional
    public void batchUpdateStatus(List<Long> ids, ManagedResource.Status status) {

    }

    public void refreshResources() {
                resourceRegistryService.refreshAndSynchronizeResources();
    }
}
