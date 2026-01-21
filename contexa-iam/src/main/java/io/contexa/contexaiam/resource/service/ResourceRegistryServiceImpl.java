package io.contexa.contexaiam.resource.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNameSuggestion;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ResourceRegistryServiceImpl implements ResourceRegistryService {
    
    private final List<ResourceScanner> scanners;
    private final ManagedResourceRepository managedResourceRepository;
    private final PermissionCatalogService permissionCatalogService;
    private final AINativeProcessor aiNativeProcessor;
    private final AutoConditionTemplateService autoConditionTemplateService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Async
    @Override
    @Transactional
    public void
    refreshAndSynchronizeResources() {

        List<ManagedResource> discoveredResources = scanners.stream()
                .flatMap(scanner -> scanner.scan().stream())
                .filter(Objects::nonNull)
                .toList();

        Map<String, List<ManagedResource>> groupedByIdentifier = discoveredResources.stream()
                .collect(Collectors.groupingBy(ManagedResource::getResourceIdentifier));

        groupedByIdentifier.forEach((identifier, list) -> {
            if (list.size() > 1) {
                log.warn("리소스 식별자 충돌 감지: '{}'이(가) {}개의 스캐너에서 발견되었습니다. 첫 번째 발견된 리소스를 사용합니다.", identifier, list.size());
            }
        });

        Map<String, ManagedResource> discoveredResourcesMap = groupedByIdentifier.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().get(0)));
        
        Map<String, ManagedResource> existingResourcesMap = managedResourceRepository.findAll().stream()
                .collect(Collectors.toMap(ManagedResource::getResourceIdentifier, Function.identity()));

        List<ManagedResource> newResources = discoveredResourcesMap.values().stream()
                .filter(discovered -> !existingResourcesMap.containsKey(discovered.getResourceIdentifier()))
                .toList();

        List<ManagedResource> removedResources = existingResourcesMap.values().stream()
                .filter(existing -> !discoveredResourcesMap.containsKey(existing.getResourceIdentifier()))
                .toList();

        if (!removedResources.isEmpty()) {
            log.warn("{}개의 리소스가 현재 코드에서 발견되지 않았습니다. (예: {})", removedResources.size(), removedResources.get(0).getResourceIdentifier());
            
        }

        if (newResources.isEmpty()) {
                    } else if (newResources.size() == 1) {
            
            processSingleResource(newResources.getFirst());
        } else {
            
            int batchSize = 10; 
            List<List<ManagedResource>> resourceBatches = Lists.partition(newResources, batchSize);
            
            List<CompletableFuture<Void>> futures = resourceBatches.stream()
                    .map(batch -> CompletableFuture.runAsync(() -> processResourceBatch(batch)))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                    }
        autoConditionTemplateService.generateConditionTemplates();
            }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processSingleResource(ManagedResource resource) {
                try {
            
            List<Map<String, String>> singleResourceList = List.of(
                Map.of("identifier", resource.getResourceIdentifier(), 
                       "owner", resource.getServiceOwner() != null ? resource.getServiceOwner() : "Unknown")
            );
            
            IAMRequest<ResourceNamingContext> request = createResourceNamingRequest(singleResourceList);

            Object rawResponse = aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();
            ResourceNamingSuggestionResponse suggestionResponse = (ResourceNamingSuggestionResponse) rawResponse;

            Map<String, ResourceNameSuggestion> suggestions = suggestionResponse.toResourceNameSuggestionMap();
            ResourceNameSuggestion suggestion = suggestions.get(resource.getResourceIdentifier());
            
            if (suggestion != null) {
                resource.setFriendlyName(suggestion.friendlyName());
                resource.setDescription(suggestion.description());
                            } else {
                
                resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                resource.setDescription("AI 추천을 받지 못한 리소스입니다.");
                log.warn("AI가 추천을 제공하지 않아 기본값을 사용합니다: {}", resource.getResourceIdentifier());
            }
            
            managedResourceRepository.save(resource);
            
        } catch (Exception e) {
            log.warn("AI 리소스 이름 추천 실패: {}. 기본값을 사용합니다.", resource.getResourceIdentifier(), e);
            resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
            resource.setDescription("AI 추천 실패로 기본값을 사용합니다.");
            managedResourceRepository.save(resource);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void processResourceBatch(List<ManagedResource> batch) {

        if (batch == null || batch.isEmpty()) {
            log.warn("배치가 비어있어 처리를 건너뜁니다.");
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
            log.warn("유효한 리소스가 없어 AI 추천을 건너뜁니다.");
            
            managedResourceRepository.saveAll(batch);
            return;
        }

        try {
            
            IAMRequest<ResourceNamingContext> request = createResourceNamingRequest(resourcesToSuggest);

            Object rawResponse = aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();
            ResourceNamingSuggestionResponse suggestionResponse = (ResourceNamingSuggestionResponse) rawResponse;

            Map<String, ResourceNameSuggestion> suggestionsMap = suggestionResponse.toResourceNameSuggestionMap();

            int appliedCount = 0;
            int skippedCount = 0;

            for (ManagedResource resource : batch) {
                if (resource.getResourceIdentifier() == null) {
                    log.warn("리소스 식별자가 null인 리소스를 건너뜁니다: {}", resource);
                    skippedCount++;
                    continue;
                }

                ResourceNameSuggestion suggestion = suggestionsMap.get(resource.getResourceIdentifier());

                if (suggestion != null) {
                    String oldFriendlyName = resource.getFriendlyName();
                    String oldDescription = resource.getDescription();

                    resource.setFriendlyName(suggestion.friendlyName());
                    resource.setDescription(suggestion.description());

                    appliedCount++;
                } else {
                    log.warn("AI가 리소스 '{}'에 대한 추천을 반환하지 않았습니다. 기본값을 유지합니다.",
                            resource.getResourceIdentifier());

                    if (resource.getFriendlyName() == null || resource.getFriendlyName().trim().isEmpty()) {
                        resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                    }
                    if (resource.getDescription() == null || resource.getDescription().trim().isEmpty()) {
                        resource.setDescription("AI 추천을 받지 못한 리소스입니다.");
                    }

                    skippedCount++;
                }
            }

            managedResourceRepository.saveAll(batch);

        } catch (Exception e) {
            log.error("AI 추천 처리 중 오류 발생. 기본값으로 저장합니다.", e);

            batch.forEach(resource -> {
                if (resource.getFriendlyName() == null || resource.getFriendlyName().trim().isEmpty()) {
                    resource.setFriendlyName(generateFallbackFriendlyName(resource.getResourceIdentifier()));
                }
                if (resource.getDescription() == null || resource.getDescription().trim().isEmpty()) {
                    resource.setDescription("AI 추천 실패로 기본값을 사용합니다.");
                }
            });

            managedResourceRepository.saveAll(batch);
                    }
    }

    private String generateFallbackFriendlyName(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            return "알 수 없는 리소스";
        }

        if (identifier.startsWith("/")) {
            String[] parts = identifier.split("/");
            for (int i = parts.length - 1; i >= 0; i--) {
                if (!parts[i].isEmpty() && !parts[i].matches("\\{.*\\}")) {  
                    return parts[i] + " 기능";
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
            return formatted + " 기능";
        }

        return identifier + " 기능";
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
        if (resource.getPermission() != null) {
            resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
        } else {
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        }
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
    @Transactional
    public void restoreResourceToManagement(Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        
        if (resource.getPermission() != null) {
            resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
        } else {
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        }
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
            
            if (status == ManagedResource.Status.NEEDS_DEFINITION) {
                if (resource.getPermission() != null) {
                    resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                } else {
                    resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
                }
            } else {
                resource.setStatus(status);
            }
        }

        managedResourceRepository.saveAll(resourcesToUpdate);
            }

    private IAMRequest<ResourceNamingContext> createResourceNamingRequest(List<Map<String, String>> resources) {
        
        ResourceNamingContext context = new ResourceNamingContext.Builder(
            SecurityLevel.STANDARD,
            AuditRequirement.BASIC
        ).withResourceBatch(resources).build();

        IAMRequest<ResourceNamingContext> request = new IAMRequest<>(context, "suggestResourceNames");
        request.withDiagnosisType(DiagnosisType.RESOURCE_NAMING);
        request.withParameter("resources", resources);
        request.withParameter("batchSize", resources.size());
        
                return request;
    }

}