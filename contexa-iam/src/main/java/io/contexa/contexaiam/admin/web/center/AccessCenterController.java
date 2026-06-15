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
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessCenterStats;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessPageResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessPermissionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleAssignmentsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleListResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleOptionResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessUserDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessUserSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateRolePermissionsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@RequestMapping("/contexa/admin/access-center")
@RequiredArgsConstructor
@Slf4j
public class AccessCenterController {

    private final AccessCenterService accessCenterService;

    @GetMapping
    public String accessCenter(
            @RequestParam(required = false, defaultValue = "users") String tab,
            Model model) {
        model.addAttribute("activePage", "access-center");
        model.addAttribute("activeTab", tab);

        AccessCenterStats stats = accessCenterService.getStats();
        model.addAttribute("userCount", stats.userCount());
        model.addAttribute("groupCount", stats.groupCount());
        model.addAttribute("roleCount", stats.roleCount());
        model.addAttribute("permissionCount", stats.permissionCount());

        return "contexa/admin/access-center";
    }

    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<AccessPageResponse<AccessUserSummaryResponse>> searchUsers(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        return ResponseEntity.ok(accessCenterService.searchUsers(keyword, pageable));
    }

    @GetMapping("/api/users/{userId}/detail")
    @ResponseBody
    public ResponseEntity<AccessUserDetailResponse> getUserDetail(@PathVariable Long userId) {
        try {
            return ResponseEntity.ok(accessCenterService.getUserDetail(userId));
        } catch (IllegalArgumentException e) {
            log.warn("Access center user detail not found: {}", userId, e);
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/api/users/{userId}/groups")
    @ResponseBody
    public ResponseEntity<AccessActionResponse> updateUserGroups(
            @PathVariable Long userId,
            @RequestBody UpdateUserGroupsRequest request) {
        try {
            return ResponseEntity.ok(accessCenterService.updateUserGroups(userId, request));
        } catch (Exception e) {
            log.error("Failed to update user groups", e);
            return ResponseEntity.badRequest().body(new AccessActionResponse(false, e.getMessage()));
        }
    }

    @PostMapping("/api/users/{userId}/roles")
    @ResponseBody
    public ResponseEntity<AccessActionResponse> updateUserDirectRoles(
            @PathVariable Long userId,
            @RequestBody AccessRoleAssignmentsRequest request) {
        try {
            return ResponseEntity.ok(accessCenterService.updateUserDirectRoles(userId, request));
        } catch (Exception e) {
            log.error("Failed to update user direct roles", e);
            return ResponseEntity.badRequest().body(new AccessActionResponse(false, e.getMessage()));
        }
    }

    @GetMapping("/api/groups")
    @ResponseBody
    public ResponseEntity<List<AccessGroupSummaryResponse>> getAllGroups() {
        return ResponseEntity.ok(accessCenterService.getAllGroups());
    }

    @GetMapping("/api/groups/{groupId}/detail")
    @ResponseBody
    public ResponseEntity<AccessGroupDetailResponse> getGroupDetail(@PathVariable Long groupId) {
        try {
            return ResponseEntity.ok(accessCenterService.getGroupDetail(groupId));
        } catch (IllegalArgumentException e) {
            log.warn("Access center group detail not found: {}", groupId, e);
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/api/groups/{groupId}/roles")
    @ResponseBody
    public ResponseEntity<AccessActionResponse> updateGroupRoles(
            @PathVariable Long groupId,
            @RequestBody AccessRoleAssignmentsRequest request) {
        try {
            return ResponseEntity.ok(accessCenterService.updateGroupRoles(groupId, request));
        } catch (Exception e) {
            log.error("Failed to update group roles", e);
            return ResponseEntity.badRequest().body(new AccessActionResponse(false, e.getMessage()));
        }
    }

    @GetMapping("/api/roles")
    @ResponseBody
    public ResponseEntity<List<AccessRoleListResponse>> getAllRoles() {
        return ResponseEntity.ok(accessCenterService.getAllRoles());
    }

    @GetMapping("/api/roles/{roleId}/detail")
    @ResponseBody
    public ResponseEntity<AccessRoleDetailResponse> getRoleDetail(@PathVariable Long roleId) {
        try {
            return ResponseEntity.ok(accessCenterService.getRoleDetail(roleId));
        } catch (IllegalArgumentException e) {
            log.warn("Access center role detail not found: {}", roleId, e);
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/api/roles/{roleId}/permissions")
    @ResponseBody
    public ResponseEntity<AccessActionResponse> updateRolePermissions(
            @PathVariable Long roleId,
            @RequestBody UpdateRolePermissionsRequest request) {
        try {
            return ResponseEntity.ok(accessCenterService.updateRolePermissions(roleId, request));
        } catch (Exception e) {
            log.error("Failed to update role permissions", e);
            return ResponseEntity.badRequest().body(new AccessActionResponse(false, e.getMessage()));
        }
    }

    @GetMapping("/api/all-groups")
    @ResponseBody
    public ResponseEntity<List<AccessGroupSummaryResponse>> getAllGroupsSimple() {
        return ResponseEntity.ok(accessCenterService.getAllGroups());
    }

    @GetMapping("/api/all-roles")
    @ResponseBody
    public ResponseEntity<List<AccessRoleOptionResponse>> getAllRolesSimple() {
        return ResponseEntity.ok(accessCenterService.getAllRolesSimple());
    }

    @GetMapping("/api/all-permissions")
    @ResponseBody
    public ResponseEntity<List<AccessPermissionSummaryResponse>> getAllPermissions() {
        return ResponseEntity.ok(accessCenterService.getAllPermissions());
    }

    @GetMapping("/api/users/{userId}/roles/{roleId}/cruds")
    @ResponseBody
    public ResponseEntity<List<String>> getUserRoleCruds(
            @PathVariable Long userId, @PathVariable Long roleId) {
        return ResponseEntity.ok(accessCenterService.getUserRoleCruds(userId, roleId));
    }

    @GetMapping("/api/groups/{groupId}/roles/{roleId}/cruds")
    @ResponseBody
    public ResponseEntity<List<String>> getGroupRoleCruds(
            @PathVariable Long groupId, @PathVariable Long roleId) {
        return ResponseEntity.ok(accessCenterService.getGroupRoleCruds(groupId, roleId));
    }
}
