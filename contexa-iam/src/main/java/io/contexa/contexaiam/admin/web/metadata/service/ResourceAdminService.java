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
package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.AdminChangeAudit;
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
import io.contexa.contexaiam.common.ConsoleFault;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class ResourceAdminService {

    private final ResourceRegistryService resourceRegistryService;
    private final ManagedResourceRepository managedResourceRepository;
    private final MessageSource messageSource;

    /** K130: a change of the resources' management is audited; without the facade nothing is recorded. */
    private AdminChangeAudit audit = AdminChangeAudit.NONE;

    /** K130: records the changes of the resources' management. */
    public void setCentralAuditFacade(CentralAuditFacade centralAuditFacade) {
        this.audit = AdminChangeAudit.of(centralAuditFacade);
    }

    /** K130: the resource's management changed: its action, the resource and what it is now. */
    private void auditResourceChange(String action, Long id, ManagedResource.Status before, Permission permission) {
        ManagedResource resource = managedResourceRepository.findById(id).orElse(null);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("resourceId", id);
        details.put("statusBefore", before != null ? before.name() : null);
        details.put("status", resource != null && resource.getStatus() != null ? resource.getStatus().name() : null);
        if (permission != null) {
            details.put("permissionId", permission.getId());
            details.put("permissionName", permission.getName());
        }
        audit.record(AuditEventCategory.RESOURCE_MANAGEMENT_CHANGED, action,
                resource != null ? resource.getResourceIdentifier() : String.valueOf(id), details);
    }

    private ManagedResource.Status statusOf(Long id) {
        return managedResourceRepository.findById(id).map(ManagedResource::getStatus).orElse(null);
    }

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
        ManagedResource.Status before = statusOf(id);
        Permission newPermission = resourceRegistryService.defineResourceAsPermission(id, toMetadataDto(metadataForm));
        auditResourceChange("RESOURCE_DEFINED", id, before, newPermission);
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
                ManagedResource.Status before = resource != null ? resource.getStatus() : null;
                Permission perm = resourceRegistryService.defineResourceAsPermission(resourceId, dto);
                auditResourceChange("RESOURCE_DEFINED", resourceId, before, perm);
                results.add(ResourceBatchDefineResult.created(
                        resourceId,
                        perm.getId(),
                        perm.getFriendlyName()
                ));
            } catch (Exception e) {
                ConsoleFault.report(e, log, "define a permission for resource " + resourceId);
                results.add(ResourceBatchDefineResult.error(resourceId, ConsoleFault.textOf(e)));
            }
        }
        return results;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public ResourceStatusResponse restoreResource(Long id) {
        // D58: restoring takes an excluded resource back into management, as excluding is refused for a resource that
        // has a permission or a policy. Run on any other, it reset a defined or connected resource to "needs
        // definition" while its permission and policies stayed.
        ManagedResource resource = managedResourceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(message("msg.resource.not.found.id", String.valueOf(id))));
        if (resource.getStatus() != ManagedResource.Status.EXCLUDED) {
            throw new IllegalStateException(message("msg.resource.restore.invalid.status", resource.getStatus()));
        }
        ResourceManagementDto dto = new ResourceManagementDto();
        dto.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        resourceRegistryService.updateResourceManagementStatus(id, dto);
        auditResourceChange("RESOURCE_RESTORED", id, ManagedResource.Status.EXCLUDED, null);
        return new ResourceStatusResponse(
                message("msg.resource.restored"),
                id,
                "NEEDS_DEFINITION"
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public ResourceStatusResponse excludeResource(Long id) {
        ManagedResource.Status before = statusOf(id);
        resourceRegistryService.excludeResourceFromManagement(id);
        if (before != ManagedResource.Status.EXCLUDED) {
            auditResourceChange("RESOURCE_EXCLUDED", id, before, null);
        }
        return new ResourceStatusResponse(
                "Resource excluded from management",
                id,
                "EXCLUDED"
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateManagementStatus(Long id, ResourceManagementForm managementForm) {
        ManagedResource.Status before = statusOf(id);
        resourceRegistryService.updateResourceManagementStatus(id, toManagementDto(managementForm));
        // a status saved as it was changed nothing
        if (statusOf(id) != before) {
            auditResourceChange("RESOURCE_STATUS_CHANGED", id, before, null);
        }
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
