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
            throw new IllegalStateException("정의가 필요한 리소스로부터 권한을 생성할 수 없습니다. 리소스 ID: " + resource.getId());
        }

        String permissionName = generatePermissionName(resource);

        Permission permission = permissionRepository.findByName(permissionName)
                .orElseGet(() -> Permission.builder().name(permissionName).build());

        permission.setFriendlyName(resource.getFriendlyName());
        permission.setDescription(resource.getDescription());
        permission.setTargetType(resource.getResourceType().name());

        String actionType = "EXECUTE"; // 메서드 기반일 때 기본값
        if (resource.getResourceType() == ManagedResource.ResourceType.URL && resource.getHttpMethod() != null) {
            actionType = resource.getHttpMethod().name();
        }
        permission.setActionType(actionType);
        permission.setManagedResource(resource);

        Permission savedPermission = permissionRepository.save(permission);
        log.info("Permission '{}' has been synchronized for resource '{}'.", savedPermission.getName(), resource.getResourceIdentifier());

        // [핵심] 권한이 생성/업데이트된 후, 이 권한에 대한 정책 동기화를 즉시 호출합니다.
//        policyService.synchronizePolicyForPermission(savedPermission);

        return savedPermission;
    }

    @Override
    @Transactional(readOnly = true)
    public List<PermissionDto> getAvailablePermissions() {
        return permissionRepository.findDefinedPermissionsWithDetails().stream()
                .map(p -> modelMapper.map(p, PermissionDto.class))
                .collect(Collectors.toList());
    }

    /**
     * ManagedResource를 기반으로 가독성이 높은 고유 권한 이름을 생성합니다.
     * - 메서드: 패키지 경로를 제외하고 '클래스명_메서드명' 형태로 생성합니다.
     * - URL: 경로 변수와 특수문자를 정리하여 'ADMIN_USERS_ID'와 같은 형태로 생성합니다.
     */
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
        String className = parts[parts.length - 2]; // 마지막에서 두 번째 (클래스명)
        String methodPart = parts[parts.length - 1].split("\\(")[0]; // 마지막 (메서드명, 괄호 제거)
        return String.format("%s_%s", className, methodPart).toUpperCase();
    }

    private String simplifyUrlIdentifier(String urlIdentifier) {
        // 예: /admin/users/{id} → ADMIN_USERS_ID
        return urlIdentifier.replaceAll("[{}]", "")
                .replaceAll("[^a-zA-Z0-9]", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "")
                .toUpperCase();
    }
}