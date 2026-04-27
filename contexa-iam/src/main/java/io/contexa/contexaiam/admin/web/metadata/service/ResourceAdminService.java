package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.EnumNameValue;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineRequest;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineResult;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceDefineResponse;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceManagementForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceMetadataForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourcePermissionView;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceSearchForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceStatusResponse;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceWorkbenchPageModel;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceWorkbenchResourceView;
import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class ResourceAdminService {

    private final ResourceRegistryService resourceRegistryService;
    private final ManagedResourceRepository managedResourceRepository;
    private final MessageSource messageSource;

    public String message(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    public ResourceWorkbenchPageModel getWorkbenchPage(ResourceSearchForm criteria, Pageable pageable) {
        Page<ManagedResource> resourcePage = resourceRegistryService.findResources(toCriteria(criteria), pageable);
        Set<String> serviceOwners = resourceRegistryService.getAllServiceOwners();
        Page<ResourceWorkbenchResourceView> viewPage = new PageImpl<>(
                resourcePage.getContent().stream().map(this::toView).toList(),
                resourcePage.getPageable(),
                resourcePage.getTotalElements()
        );
        return new ResourceWorkbenchPageModel(viewPage, serviceOwners, criteria);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void refreshResources() {
        resourceRegistryService.refreshAndSynchronizeResources();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public ResourceDefineResponse defineResourceAsPermission(Long id, ResourceMetadataForm metadataForm) {
        Permission newPermission = resourceRegistryService.defineResourceAsPermission(id, toMetadataDto(metadataForm));
        return new ResourceDefineResponse(
                message("msg.resource.permission.created"),
                newPermission.getId(),
                newPermission.getFriendlyName()
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public List<ResourceBatchDefineResult> defineResourcesBatch(List<ResourceBatchDefineRequest> requests) {
        List<ResourceBatchDefineResult> results = new ArrayList<>();
        for (ResourceBatchDefineRequest req : requests) {
            if (req.resourceId() == null) {
                results.add(ResourceBatchDefineResult.missingResourceId());
                continue;
            }
            Long resourceId = req.resourceId();
            String friendlyName = req.friendlyName();
            String description = req.description();
            try {
                ManagedResource resource = managedResourceRepository.findById(resourceId).orElse(null);
                if (resource != null && resource.getPermission() != null) {
                    Permission existing = resource.getPermission();
                    results.add(ResourceBatchDefineResult.skipped(
                            resourceId,
                            existing.getId(),
                            existing.getFriendlyName() != null ? existing.getFriendlyName() : ""
                    ));
                    continue;
                }
                ResourceMetadataDto dto = new ResourceMetadataDto();
                dto.setFriendlyName(friendlyName);
                dto.setDescription(description);
                Permission perm = resourceRegistryService.defineResourceAsPermission(resourceId, dto);
                results.add(ResourceBatchDefineResult.created(
                        resourceId,
                        perm.getId(),
                        perm.getFriendlyName()
                ));
            } catch (Exception e) {
                log.error("Batch define failed for resource ID: {}", resourceId, e);
                results.add(ResourceBatchDefineResult.error(resourceId, e.getMessage()));
            }
        }
        return results;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public ResourceStatusResponse restoreResource(Long id) {
        ResourceManagementDto dto = new ResourceManagementDto();
        dto.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        resourceRegistryService.updateResourceManagementStatus(id, dto);
        return new ResourceStatusResponse(
                "Resource restored to management",
                id,
                "NEEDS_DEFINITION"
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public ResourceStatusResponse excludeResource(Long id) {
        resourceRegistryService.excludeResourceFromManagement(id);
        return new ResourceStatusResponse(
                "Resource excluded from management",
                id,
                "EXCLUDED"
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateManagementStatus(Long id, ResourceManagementForm managementForm) {
        resourceRegistryService.updateResourceManagementStatus(id, toManagementDto(managementForm));
    }

    private ResourceWorkbenchResourceView toView(ManagedResource resource) {
        return new ResourceWorkbenchResourceView(
                resource.getId(),
                resource.getResourceIdentifier(),
                enumValue(resource.getResourceType()),
                enumValue(resource.getHttpMethod()),
                resource.getFriendlyName(),
                resource.getDescription(),
                resource.getServiceOwner(),
                resource.getParameterTypes(),
                resource.getReturnType(),
                resource.getApiDocsUrl(),
                resource.getSourceCodeLocation(),
                resource.getAvailableContextVariables(),
                enumValue(resource.getStatus()),
                toPermissionView(resource.getPermission()),
                resource.getCreatedAt(),
                resource.getUpdatedAt()
        );
    }

    private ResourcePermissionView toPermissionView(Permission permission) {
        if (permission == null) {
            return null;
        }
        return new ResourcePermissionView(
                permission.getId(),
                permission.getName(),
                permission.getFriendlyName(),
                permission.getDescription()
        );
    }

    private ResourceSearchCriteria toCriteria(ResourceSearchForm form) {
        ResourceSearchCriteria criteria = new ResourceSearchCriteria();
        criteria.setKeyword(form.getKeyword());
        criteria.setServiceOwner(form.getServiceOwner());
        if (hasText(form.getResourceType())) {
            criteria.setResourceType(ManagedResource.ResourceType.valueOf(form.getResourceType()));
        }
        if (hasText(form.getStatus())) {
            criteria.setStatus(ManagedResource.Status.valueOf(form.getStatus()));
        }
        return criteria;
    }

    private ResourceMetadataDto toMetadataDto(ResourceMetadataForm form) {
        ResourceMetadataDto dto = new ResourceMetadataDto();
        dto.setFriendlyName(form.getFriendlyName());
        dto.setDescription(form.getDescription());
        dto.setServiceOwner(form.getServiceOwner());
        return dto;
    }

    private ResourceManagementDto toManagementDto(ResourceManagementForm form) {
        ResourceManagementDto dto = new ResourceManagementDto();
        if (hasText(form.getStatus())) {
            dto.setStatus(ManagedResource.Status.valueOf(form.getStatus()));
        }
        return dto;
    }

    private EnumNameValue enumValue(Enum<?> value) {
        return value != null ? new EnumNameValue(value.name()) : null;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
