package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.BusinessActionDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexacommon.entity.business.BusinessAction;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class WorkbenchMetadataController {

    private final BusinessMetadataService businessMetadataService;
    private final ModelMapper modelMapper;
    private final PermissionCatalogService permissionCatalogService;

    @GetMapping({"/api/admin/metadata/subjects", "/api/workbench/metadata/subjects"})
    public ResponseEntity<Map<String, Object>> getSubjectsForStudio() {
        Map<String, Object> response = new HashMap<>();
        response.put("users", businessMetadataService.getAllUsersForPolicy());
        response.put("groups", businessMetadataService.getAllGroupsForPolicy());
        response.put("roles", businessMetadataService.getAllRoles());
        response.put("permissions", permissionCatalogService.getAvailablePermissions());
        return ResponseEntity.ok(response);
    }

    @GetMapping({"/api/admin/metadata/actions", "/api/workbench/metadata/actions"})
    public ResponseEntity<List<BusinessActionDto>> getActions(@RequestParam Long resourceId) {
        List<BusinessAction> businessActions = businessMetadataService.getActionsForResource(resourceId);
        return ResponseEntity.ok(businessActions.stream()
                .map(action -> modelMapper.map(action, BusinessActionDto.class))
                .toList());
    }

    @GetMapping({"/api/admin/metadata/roles", "/api/workbench/metadata/roles"})
    public ResponseEntity<List<RoleMetadataDto>> getRoles() {
        return ResponseEntity.ok(businessMetadataService.getAllRoles());
    }

    @GetMapping({"/api/admin/metadata/authoring-metadata", "/api/workbench/metadata/authoring-metadata"})
    public ResponseEntity<Map<String, Object>> getPolicyAuthoringMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("subjects", businessMetadataService.getAllUsersAndGroups());
        metadata.put("resources", businessMetadataService.getAllBusinessResources());
        metadata.put("actions", businessMetadataService.getAllBusinessActions());
        metadata.put("conditionTemplates", businessMetadataService.getAllConditionTemplates());
        return ResponseEntity.ok(metadata);
    }

    @GetMapping({"/api/admin/metadata/permissions", "/api/workbench/metadata/permissions"})
    public ResponseEntity<List<PermissionDto>> getAvailablePermissions() {
        List<PermissionDto> permissions = permissionCatalogService.getAvailablePermissions();
        return ResponseEntity.ok(permissions);
    }
}
