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

import java.util.Locale;
import java.util.Objects;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacore.exception.StrategicOperationConflictException;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
public class ResourceRegistryServiceImpl implements ResourceRegistryService {

    /** Resources the model names in one request. */
    static final int NAMING_BATCH_SIZE = 100;

    private final List<ResourceScanner> scanners;
    private final ManagedResourceRepository managedResourceRepository;
    private final PermissionCatalogService permissionCatalogService;
    private final AICoreOperations<ResourceNamingContext> aiNativeProcessor;
    private final AutoConditionTemplateService autoConditionTemplateService;
    private final PolicyRepository policyRepository;
    private final IamAdminProperties iamAdminProperties;
    private final MessageSource messageSource;
    private final Executor namingExecutor;

    public ResourceRegistryServiceImpl(List<ResourceScanner> scanners,
                                       ManagedResourceRepository managedResourceRepository,
                                       PermissionCatalogService permissionCatalogService,
                                       AICoreOperations<ResourceNamingContext> aiNativeProcessor,
                                       AutoConditionTemplateService autoConditionTemplateService,
                                       PolicyRepository policyRepository,
                                       IamAdminProperties iamAdminProperties,
                                       MessageSource messageSource) {
        this(scanners, managedResourceRepository, permissionCatalogService, aiNativeProcessor,
                autoConditionTemplateService, policyRepository, iamAdminProperties, messageSource,
                defaultNamingExecutor());
    }

    public ResourceRegistryServiceImpl(List<ResourceScanner> scanners,
                                       ManagedResourceRepository managedResourceRepository,
                                       PermissionCatalogService permissionCatalogService,
                                       AICoreOperations<ResourceNamingContext> aiNativeProcessor,
                                       AutoConditionTemplateService autoConditionTemplateService,
                                       PolicyRepository policyRepository,
                                       IamAdminProperties iamAdminProperties,
                                       MessageSource messageSource,
                                       Executor namingExecutor) {
        this.scanners = scanners;
        this.managedResourceRepository = managedResourceRepository;
        this.permissionCatalogService = permissionCatalogService;
        this.aiNativeProcessor = aiNativeProcessor;
        this.autoConditionTemplateService = autoConditionTemplateService;
        this.policyRepository = policyRepository;
        this.iamAdminProperties = iamAdminProperties;
        this.messageSource = messageSource;
        this.namingExecutor = Objects.requireNonNull(namingExecutor, "namingExecutor");
    }

    /**
     * One daemon thread names discovered resources, one refresh after another: a refresh answers once the resources are
     * registered, and two refreshes never ask the model to name the same resources at the same time.
     */
    private static Executor defaultNamingExecutor() {
        return Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "contexa-resource-naming");
            thread.setDaemon(true);
            return thread;
        });
    }

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
            log.info("{} resources not found in current code (e.g. {})", removedResources.size(), removedResources.get(0).getResourceIdentifier());
        }

        if (!newResources.isEmpty()) {
            // New resources are registered now, under the scanner's names (or fallback names). The model names them
            // after this refresh commits, so the request does not wait for the model.
            newResources.forEach(this::applyFallback);
            List<ManagedResource> registered = managedResourceRepository.saveAll(newResources);
            scheduleNaming(registered == null ? List.of() : registered.stream()
                    .map(ManagedResource::getId)
                    .filter(Objects::nonNull)
                    .toList());
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
                log.info("Resource status reverted to PERMISSION_CREATED (no matching policy): {}", resource.getResourceIdentifier());
            }
        }
    }

    /** Names the registered resources in the background once the refresh that registered them has committed. */
    private void scheduleNaming(List<Long> resourceIds) {
        if (resourceIds.isEmpty()) {
            return;
        }
        Runnable naming = () -> nameRegisteredResources(resourceIds);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    submitNaming(naming, resourceIds.size());
                }
            });
        } else {
            submitNaming(naming, resourceIds.size());
        }
    }

    private void submitNaming(Runnable naming, int count) {
        try {
            namingExecutor.execute(naming);
            log.info("Resource naming scheduled in the background for {} new resources", count);
        } catch (RejectedExecutionException e) {
            log.warn("Resource naming could not be scheduled; {} new resources keep their registered names", count);
        }
    }

    /**
     * Names resources a refresh registered, batch by batch. Only resources still awaiting definition are named; one an
     * administrator defined, edited or excluded meanwhile is left as it is.
     */
    void nameRegisteredResources(List<Long> resourceIds) {
        for (List<Long> ids : Batches.of(resourceIds, NAMING_BATCH_SIZE)) {
            try {
                List<ManagedResource> batch = managedResourceRepository.findAllById(ids).stream()
                        .filter(resource -> resource.getStatus() == ManagedResource.Status.NEEDS_DEFINITION)
                        .toList();
                processResourceBatch(batch);
            } catch (StrategicOperationConflictException e) {
                log.warn("An identical resource naming request is already running; it names these {} resources",
                        ids.size());
            } catch (RuntimeException e) {
                log.error("Background resource naming failed; {} resources keep their registered names", ids.size(), e);
            }
        }
    }

    /**
     * Names one batch with the model and saves it. A stored resource is read again after the model answers and named
     * only if nobody changed it meanwhile, so that an administrator's definition is never replaced by a late answer.
     */
    public void processResourceBatch(List<ManagedResource> batch) {

        if (batch == null || batch.isEmpty()) {
            log.debug("Empty batch, skipping processing");
            return;
        }

        List<Map<String, String>> resourcesToSuggest = batch.stream()
                .filter(Objects::nonNull)
                .filter(r -> r.getResourceIdentifier() != null && !r.getResourceIdentifier().trim().isEmpty())
                .map(this::toResourceNamingInput)
                .collect(Collectors.toList());

        if (resourcesToSuggest.isEmpty()) {
            log.debug("No valid resources, skipping AI suggestion");
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
                log.warn("AI did not return a resource naming response; applying fallback for requested resources");
            } else {
                if (!failedIdentifiers.isEmpty()) {
                    log.warn("AI resource naming response contained invalid entries: {}", failedIdentifiers);
                }
                if (!unexpectedIdentifiers.isEmpty()) {
                    log.warn("AI resource naming response contained identifiers that were not requested: {}", unexpectedIdentifiers);
                }
                if (!missingIdentifiers.isEmpty()) {
                    log.warn("AI resource naming response missed {} of {} requested identifiers: {}",
                            missingIdentifiers.size(), requestedIdentifiers.size(), missingIdentifiers);
                }
            }

            List<ManagedResource> targets = unchangedSince(batch);
            for (ManagedResource resource : targets) {
                ResourceNameSuggestion suggestion = suggestionsMap.get(resource.getResourceIdentifier());

                if (suggestion != null) {
                    resource.setFriendlyName(suggestion.friendlyName());
                    resource.setDescription(suggestion.description());
                } else {
                    log.debug("AI did not return suggestion for resource '{}', keeping default", resource.getResourceIdentifier());
                    applyFallback(resource);
                }
            }

            managedResourceRepository.saveAll(targets);

        } catch (StrategicOperationConflictException e) {
            // An identical naming request is already running and writes the real names: these resources are neither
            // named by default nor saved here, or the defaults could replace what that request saves.
            throw e;
        } catch (Exception e) {
            log.error("AI suggestion processing failed, saving with defaults", e);
            List<ManagedResource> targets = unchangedSince(batch);
            targets.forEach(this::applyFallback);
            managedResourceRepository.saveAll(targets);
        }
    }

    /**
     * The resources of a batch as stored now, for those nobody changed since the batch was read (same status, name and
     * description). A resource not stored yet has no other writer and is used as given.
     */
    private List<ManagedResource> unchangedSince(List<ManagedResource> batch) {
        List<Long> ids = batch.stream().map(ManagedResource::getId).filter(Objects::nonNull).toList();
        Map<Long, ManagedResource> stored = ids.isEmpty() ? Map.of()
                : managedResourceRepository.findAllById(ids).stream()
                .collect(Collectors.toMap(ManagedResource::getId, Function.identity(), (first, ignored) -> first));
        List<ManagedResource> targets = new ArrayList<>();
        for (ManagedResource resource : batch) {
            if (resource.getId() == null) {
                targets.add(resource);
                continue;
            }
            ManagedResource current = stored.get(resource.getId());
            if (current != null && current.getStatus() == resource.getStatus()
                    && Objects.equals(current.getFriendlyName(), resource.getFriendlyName())
                    && Objects.equals(current.getDescription(), resource.getDescription())) {
                targets.add(current);
            } else {
                log.debug("Resource '{}' changed while it was being named; its current values are kept",
                        resource.getResourceIdentifier());
            }
        }
        return targets;
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

            String formatted = lastPart.replaceAll("([a-z])([A-Z])", "$1 $2").toLowerCase(Locale.ROOT);
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
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.resource.not.found.id", String.valueOf(resourceId))));
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
