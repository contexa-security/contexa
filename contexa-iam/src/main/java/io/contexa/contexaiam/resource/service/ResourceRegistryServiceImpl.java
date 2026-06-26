/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import io.contexa.contexaiam.resource.util.ResourceTargetKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
    private final PolicyRepository policyRepository;
    private final IamAdminProperties iamAdminProperties;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void refreshAndSynchronizeResources() {

        List<ManagedResource> discoveredResources = scanners.stream()
                .flatMap(scanner -> scanner.scan().stream())
                .filter(Objects::nonNull)
                .toList();

        Map<String, List<ManagedResource>> groupedByIdentifier = discoveredResources.stream()
                .collect(Collectors.groupingBy(ManagedResource::getResourceIdentifier));

        groupedByIdentifier.forEach((identifier, list) -> {
            if (list.size() > 1) {
//                log.error("Resource identifier conflict detected: '{}' found in {} scanners, using first occurrence", identifier, list.size());
            }
        });


        Map<String, ManagedResource> discoveredResourcesMap = groupedByIdentifier.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().get(0)));

        Map<String, ManagedResource> existingResourcesMap = managedResourceRepository.findAllWithPermission().stream()
                .collect(Collectors.toMap(ManagedResource::getResourceIdentifier, Function.identity()));

        List<ManagedResource> newResources = discoveredResourcesMap.values().stream()
                .filter(discovered -> !existingResourcesMap.containsKey(discovered.getResourceIdentifier()))
                .toList();

        List<ManagedResource> removedResources = existingResourcesMap.values().stream()
                .filter(existing -> !discoveredResourcesMap.containsKey(existing.getResourceIdentifier()))
                .toList();

        if (!removedResources.isEmpty()) {
            log.error("{} resources not found in current code (e.g. {})", removedResources.size(), removedResources.get(0).getResourceIdentifier());
        }

        if (!newResources.isEmpty()) {
            int batchSize = 100;
            List<List<ManagedResource>> resourceBatches = Lists.partition(newResources, batchSize);
            resourceBatches.forEach(this::processResourceBatch);
        }
        if (iamAdminProperties.getConditionTemplates().isEnabled()) {
            autoConditionTemplateService.generateConditionTemplates();
        }
        synchronizeResourcePolicyStatus();
    }


    private void synchronizeResourcePolicyStatus() {
        List<ManagedResource> connectedResources = managedResourceRepository
                .findByStatusInWithPermission(List.of(ManagedResource.Status.POLICY_CONNECTED));
        if (connectedResources.isEmpty()) return;

        Set<String> allPolicyTargets = policyRepository.findAllWithDetails().stream()
                .flatMap(p -> p.getTargets().stream())
                .map(ResourceTargetKey::ofPolicyTarget)
                .collect(Collectors.toSet());

        for (ManagedResource resource : connectedResources) {
            String key = ResourceTargetKey.ofResource(resource);
            if (!allPolicyTargets.contains(key)) {
                resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                managedResourceRepository.save(resource);
                log.error("Resource status reverted to PERMISSION_CREATED (no matching policy): {}", resource.getResourceIdentifier());
            }
        }
    }

    public void processResourceBatch(List<ManagedResource> batch) {

        if (batch == null || batch.isEmpty()) {
            log.error("Empty batch, skipping processing");
            return;
        }

        List<Map<String, String>> resourcesToSuggest = batch.stream()
                .filter(Objects::nonNull)
                .filter(r -> r.getResourceIdentifier() != null && !r.getResourceIdentifier().trim().isEmpty())
                .map(this::toResourceNamingInput)
                .collect(Collectors.toList());

        if (resourcesToSuggest.isEmpty()) {
            log.error("No valid resources, skipping AI suggestion");
            batch.forEach(this::applyFallback);
            managedResourceRepository.saveAll(batch);
            return;
        }

        try {
            AIRequest<ResourceNamingContext> request = createResourceNamingRequest(resourcesToSuggest);
            ResourceNamingSuggestionResponse suggestionResponse =
                    aiNativeProcessor.process(request, ResourceNamingSuggestionResponse.class).block();

            Set<String> requestedIdentifiers = resourcesToSuggest.stream()
                    .map(resource -> resource.get("identifier"))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            Map<String, ResourceNameSuggestion> suggestionsMap = suggestionResponse == null
                    ? Map.of()
                    : suggestionResponse.toResourceNameSuggestionMap().entrySet().stream()
                    .filter(entry -> requestedIdentifiers.contains(entry.getKey()))
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (first, ignored) -> first,
                            LinkedHashMap::new
                    ));

            Set<String> responseIdentifiers = suggestionResponse == null
                    ? Set.of()
                    : suggestionResponse.getSuggestions().stream()
                    .map(ResourceNamingSuggestionResponse.ResourceNamingSuggestion::getIdentifier)
                    .filter(Objects::nonNull)
                    .filter(identifier -> !identifier.trim().isEmpty())
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            Set<String> missingIdentifiers = new LinkedHashSet<>(requestedIdentifiers);
            missingIdentifiers.removeAll(suggestionsMap.keySet());
            Set<String> unexpectedIdentifiers = new LinkedHashSet<>(responseIdentifiers);
            unexpectedIdentifiers.removeAll(requestedIdentifiers);
            List<String> failedIdentifiers = suggestionResponse == null
                    ? List.of()
                    : suggestionResponse.getFailedIdentifiers();

            if (suggestionResponse == null) {
                log.error("AI did not return a resource naming response; applying fallback for requested resources");
            } else {
                if (!failedIdentifiers.isEmpty()) {
                    log.error("AI resource naming response contained invalid entries: {}", failedIdentifiers);
                }
                if (!unexpectedIdentifiers.isEmpty()) {
                    log.error("AI resource naming response contained identifiers that were not requested: {}", unexpectedIdentifiers);
                }
                if (!missingIdentifiers.isEmpty()) {
                    log.error("AI resource naming response missed {} of {} requested identifiers: {}",
                            missingIdentifiers.size(), requestedIdentifiers.size(), missingIdentifiers);
                }
            }

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

    private Map<String, String> toResourceNamingInput(ManagedResource resource) {
        Map<String, String> input = new LinkedHashMap<>();
        putIfPresent(input, "identifier", resource.getResourceIdentifier());
        putIfPresent(input, "owner", resource.getServiceOwner() != null ? resource.getServiceOwner() : "Unknown");
        putIfPresent(input, "resourceType", resource.getResourceType() != null ? resource.getResourceType().name() : null);
        putIfPresent(input, "httpMethod", resource.getHttpMethod() != null ? resource.getHttpMethod().name() : null);
        putIfPresent(input, "serviceOwner", resource.getServiceOwner());
        putIfPresent(input, "scannerFriendlyNameHint", resource.getFriendlyName());
        putIfPresent(input, "scannerDescriptionHint", resource.getDescription());
        putIfPresent(input, "parameterTypes", resource.getParameterTypes());
        putIfPresent(input, "returnType", resource.getReturnType());
        putIfPresent(input, "apiDocsUrl", resource.getApiDocsUrl());
        putIfPresent(input, "sourceCodeLocation", resource.getSourceCodeLocation());
        return input;
    }

    private void putIfPresent(Map<String, String> target, String key, String value) {
        if (value != null && !value.trim().isEmpty()) {
            target.put(key, value);
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
    @Transactional(transactionManager = "contexaTransactionManager")
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
    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateResourceManagementStatus(Long resourceId, ResourceManagementDto managedDto) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found with ID: " + resourceId));
        resource.setStatus(resolveStatus(resource, managedDto.getStatus()));
        managedResourceRepository.save(resource);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<ManagedResource> findResources(ResourceSearchCriteria criteria, Pageable pageable) {
        return managedResourceRepository.findByCriteria(criteria, pageable);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void excludeResourceFromManagement(Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.resource.not.found.id", resourceId)));
        if (resource.getStatus() != ManagedResource.Status.NEEDS_DEFINITION) {
            throw new IllegalStateException(msg("msg.resource.exclude.invalid.status", resource.getStatus()));
        }
        resource.setStatus(ManagedResource.Status.EXCLUDED);
        managedResourceRepository.save(resource);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Set<String> getAllServiceOwners() {
        return managedResourceRepository.findAllServiceOwners();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
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
        // Exclude is only allowed from NEEDS_DEFINITION, so restore always returns to NEEDS_DEFINITION
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
