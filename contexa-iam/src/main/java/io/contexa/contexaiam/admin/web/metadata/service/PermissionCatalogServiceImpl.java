package io.contexa.contexaiam.admin.web.metadata.service;

import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class PermissionCatalogServiceImpl implements PermissionCatalogService {

    private final PermissionRepository permissionRepository;
    private final ModelMapper modelMapper;
    private final PolicyService policyService;

    @Override
    @Transactional
    public Permission synchronizePermissionFor(ManagedResource resource) {
        if (resource.getStatus() == ManagedResource.Status.NEEDS_DEFINITION) {
            throw new IllegalStateException("Cannot create permission from a resource that needs definition. Resource ID: " + resource.getId());
        }

        String permissionName = generatePermissionName(resource);

        Permission permission = permissionRepository.findByName(permissionName)
                .orElseGet(() -> Permission.builder().name(permissionName).build());

        permission.setFriendlyName(resource.getFriendlyName());
        permission.setDescription(resource.getDescription());
        permission.setTargetType(resource.getResourceType().name());

        String actionType = "EXECUTE"; 
        if (resource.getResourceType() == ManagedResource.ResourceType.URL && resource.getHttpMethod() != null) {
            actionType = resource.getHttpMethod().name();
        }
        permission.setActionType(actionType);
        permission.setManagedResource(resource);

        Permission savedPermission = permissionRepository.save(permission);

        return savedPermission;
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionDto> getAvailablePermissions() {
        return permissionRepository.findDefinedPermissionsWithDetails().stream()
                .map(p -> modelMapper.map(p, PermissionDto.class))
                .collect(Collectors.toList());
    }

    private String generatePermissionName(ManagedResource resource) {
        String typePrefix = resource.getResourceType().name();
        String identifierPart;

        if (resource.getResourceType() == ManagedResource.ResourceType.METHOD) {
            identifierPart = simplifyMethodIdentifier(resource.getResourceIdentifier());
        } else if (resource.getResourceType() == ManagedResource.ResourceType.URL) {
            identifierPart = simplifyUrlIdentifier(resource.getResourceIdentifier());
        } else {
            identifierPart = resource.getResourceIdentifier().replaceAll("[^a-zA-Z0-9]", "_").toUpperCase();
        }

        return String.format("%s_%s", typePrefix, identifierPart).replaceAll("_+", "_");
    }

    private String simplifyMethodIdentifier(String methodIdentifier) {
        String[] parts = methodIdentifier.split("\\.");
        String className = parts[parts.length - 2]; 
        String methodPart = parts[parts.length - 1].split("\\(")[0]; 
        return String.format("%s_%s", className, methodPart).toUpperCase();
    }

    private String simplifyUrlIdentifier(String urlIdentifier) {
        
        return urlIdentifier.replaceAll("[{}]", "")
                .replaceAll("[^a-zA-Z0-9]", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "")
                .toUpperCase();
    }
}