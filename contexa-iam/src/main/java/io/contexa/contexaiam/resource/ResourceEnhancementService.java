package io.contexa.contexaiam.resource;

import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ResourceEnhancementService {

    private final ResourceRegistryService resourceRegistryService;

    public void refreshResources() {
        resourceRegistryService.refreshAndSynchronizeResources();
    }
}
