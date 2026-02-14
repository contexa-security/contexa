package io.contexa.contexaiam.resource.service;

import com.google.common.collect.Lists;
import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ResourceRegistryServiceImpl implements ResourceRegistryService {

    private final List<ResourceScanner> scanners;
    private final ManagedResourceRepository managedResourceRepository;
    private final PermissionCatalogService permissionCatalogService;
    private final AICoreOperations<ResourceNamingContext> aiNativeProcessor;
    private final AutoConditionTemplateService autoConditionTemplateService;

    @Async
    @Override
    @Transactional
    public void refreshAndSynchronizeResources() {

        List<ManagedResource> discoveredResources = scanners.stream()
                .flatMap(scanner -> scanner.scan().stream())
                .filter(Objects::nonNull)
                .toList();

        Map<String, List<ManagedResource>> groupedByIdentifier = discoveredResources.stream()
                .collect(Collectors.groupingBy(ManagedResource::getResourceIdentifier));

        groupedByIdentifier.forEach((identifier, list) -> {
            if (list.size() > 1) {
                log.error("Resource identifier conflict detected: '{}' found in {} scanners, using first occurrence", identifier, list.size());
            }
        });

        Map<String, ManagedResource> discoveredResourcesMap = groupedByIdentifier.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().getFirst()));

        Map<String, ManagedResource> existingResourcesMap = managedResourceRepository.findAll().stream()
                .collect(Collectors.toMap(ManagedResource::getResourceIdentifier, Function.identity()));

        List<ManagedResource> newResources = discoveredResourcesMap.values().stream()
                .filter(discovered -> !existingResourcesMap.containsKey(discovered.getResourceIdentifier()))
                .toList();

        List<ManagedResource> removedResources = existingResourcesMap.values().stream()
                .filter(existing -> !discoveredResourcesMap.containsKey(existing.getResourceIdentifier()))
                .toList();

        if (!removedResources.isEmpty()) {
            log.error("{} resources not found in current code (e.g. {})", removedResources.size(), removedResources.getFirst().getResourceIdentifier());
        }

        if (!newResources.isEmpty()) {
            int batchSize = 10;
            List<List<ManagedResource>> resourceBatches = Lists.partition(newResources, batchSize);
            resourceBatches.forEach(this::processResourceBatch);
        }
        autoConditionTemplateService.generateConditionTemplates();
    }

    public void processResourceBatch(List<ManagedResource> batch) {

        if (batch == null || batch.isEmpty()) {
            log.error("Empty batch, skipping processing");
            return;
        }

        List<Map<String, String>> resourcesToSuggest = batch.stream()
                .filter(Objects::nonNull)
                .filter(r -> r.getResourceIdentifier() != null && !r.getResourceIdentifier().trim().isEmpty())
                .map(r -> {
                    String identifier = r.getResourceIdentifier();
                    String owner = r.getServiceOwner() != null ? r.getServiceOwner() : "Unknown";

                    return Map.of("identifier", identifier, "owner", owner);
                })
                .collect(Collectors.toList());

        if (resourcesToSuggest.isEmpty()) {
            log.error("No valid resources, skipping AI suggestion");
            managedResourceRepository.saveAll(batch);
            return;
        }

        try {
            AIRequest<ResourceNamingContext> request = createResourceNamingRequest(resourcesToSuggest);
            ResourceNamingSuggestionResponse suggestionResponse =
                    aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();

            Map<String, ResourceNameSuggestion> suggestionsMap = suggestionResponse.toResourceNameSuggestionMap();

            for (ManagedResource resource : batch) {
                ResourceNameSuggestion suggestion = suggestionsMap.get(resource.getResourceIdentifier());

                if (suggestion != null) {
                    resource.setFriendlyName(suggestion.friendlyName());
                    resource.setDescription(suggestion.description());
                } else {
                    log.error("AI did not return suggestion for resource '{}', keeping default", resource.getResourceIdentifier());
                    applyFallback(resource);
                }
            }

            managedResourceRepository.saveAll(batch);

        } catch (Exception e) {
            log.error("AI suggestion processing failed, saving with defaults", e);
            batch.forEach(this::applyFallback);
            managedResourceRepository.saveAll(batch);
        }
    }

    private String generateFallbackFriendlyName(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return "Unknown Resource";
        }

        if (identifier.startsWith("/")) {
            String[] parts = identifier.split("/");
            for (int i = parts.length - 1; i >= 0; i--) {
                if (!parts[i].isEmpty() && !parts[i].matches("\\{.*\\}")) {
                    return parts[i] + " Feature";
                }
            }
        }

        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.");
            String lastPart = parts[parts.length - 1];
            if (lastPart.contains("()")) {
                lastPart = lastPart.replace("()", "");
            }

            String formatted = lastPart.replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase();
            return formatted + " Feature";
        }

        return identifier + " Feature";
    }

    @Override
    @Transactional
    public Permission defineResourceAsPermission(Long resourceId, ResourceMetadataDto metadataDto) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));

        resource.setFriendlyName(metadataDto.getFriendlyName());
        resource.setDescription(metadataDto.getDescription());
        resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);

        ManagedResource savedResource = managedResourceRepository.save(resource);

        return permissionCatalogService.synchronizePermissionFor(savedResource);
    }

    @Override
    @Transactional
    public void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        resource.setStatus(resolveStatus(resource, managedDto.getStatus()));
        managedResourceRepository.save(resource);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ManagedResource> findResources(ResourceSearchCriteria criteria, Pageable pageable) {
        return managedResourceRepository.findByCriteria(criteria, pageable);
    }

    @Override
    @Transactional
    public void excludeResourceFromManagement(Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        resource.setStatus(ManagedResource.Status.EXCLUDED);
        managedResourceRepository.save(resource);
    }

    @Override
    @Transactional(readOnly = true)
    public Set<String> getAllServiceOwners() {
        return managedResourceRepository.findAllServiceOwners();
    }

    @Override
    @Transactional
    public void batchUpdateStatus(List<Long> ids, ManagedResource.Status status) {
        if (CollectionUtils.isEmpty(ids)) {
            return;
        }
        List<ManagedResource> resourcesToUpdate = managedResourceRepository.findAllById(ids);
        if (resourcesToUpdate.isEmpty()) {
            return;
        }
        for (ManagedResource resource : resourcesToUpdate) {
            resource.setStatus(resolveStatus(resource, status));
        }

        managedResourceRepository.saveAll(resourcesToUpdate);
    }

    private ManagedResource.Status resolveStatus(ManagedResource resource, ManagedResource.Status requestedStatus) {
        if (requestedStatus == ManagedResource.Status.NEEDS_DEFINITION && resource.getPermission() != null) {
            return ManagedResource.Status.PERMISSION_CREATED;
        }
        return requestedStatus;
    }

    private void applyFallback(ManagedResource resource) {
        if (resource.getFriendlyName() == null || resource.getFriendlyName().trim().isEmpty()) {
            resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
        }
        if (resource.getDescription() == null || resource.getDescription().trim().isEmpty()) {
            resource.setDescription("AI suggestion unavailable");
        }
    }

    private AIRequest<ResourceNamingContext> createResourceNamingRequest(List<Map<String, String>> resources) {
        ResourceNamingContext context = new ResourceNamingContext.Builder().withResourceBatch(resources).build();

        ResourceNamingSuggestionRequest request = new ResourceNamingSuggestionRequest(context, new TemplateType("ResourceNaming"), new DiagnosisType("ResourceNaming"));
        List<ResourceNamingSuggestionRequest.ResourceItem> items = resources.stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::fromMap)
                .toList();
        request.setResources(items);

        request.withParameter("resources", resources);
        List<String> identifiers = resources.stream()
                .map(r -> r.get("identifier"))
                .toList();
        request.withParameter("identifiers", identifiers);

        return request;
    }
}