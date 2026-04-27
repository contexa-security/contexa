package io.contexa.contexaiam.admin.web.center.dto;

import java.util.Collections;
import java.util.List;

public final class AccessCenterDtos {

    private AccessCenterDtos() {
    }

    public record AccessCenterStats(
            long userCount,
            long groupCount,
            long roleCount,
            long permissionCount
    ) {
    }

    public record AccessPageResponse<T>(
            List<T> content,
            long totalElements,
            int totalPages
    ) {
    }

    public record AccessActionResponse(
            boolean success,
            String message
    ) {
    }

    public record AccessUserSummaryResponse(
            Long id,
            String username,
            String name,
            String email,
            boolean enabled,
            String department
    ) {
    }

    public record AccessUserDetailResponse(
            Long id,
            String username,
            String name,
            String email,
            String department,
            boolean enabled,
            List<AccessGroupReferenceResponse> groups,
            List<AccessRoleSourceResponse> directRoles,
            List<AccessGroupRoleSourceResponse> groupRoles,
            List<AccessPermissionSourceResponse> permissions
    ) {
    }

    public record AccessGroupSummaryResponse(
            Long id,
            String name,
            String description
    ) {
    }

    public record AccessGroupReferenceResponse(
            Long id,
            String name
    ) {
    }

    public record AccessGroupDetailResponse(
            Long id,
            String name,
            String description,
            List<AccessRoleSummaryResponse> roles,
            List<AccessUserMemberResponse> members
    ) {
    }

    public record AccessUserMemberResponse(
            Long id,
            String username,
            String name
    ) {
    }

    public record AccessRoleSummaryResponse(
            Long id,
            String name,
            String desc
    ) {
    }

    public record AccessRoleListResponse(
            Long id,
            String name,
            String desc,
            int permCount
    ) {
    }

    public record AccessRoleOptionResponse(
            Long id,
            String name,
            String desc,
            List<String> crudPermissions,
            List<AccessPermissionSummaryResponse> extraPermissions
    ) {
    }

    public record AccessRoleSourceResponse(
            Long id,
            String name,
            String desc,
            String source
    ) {
    }

    public record AccessGroupRoleSourceResponse(
            Long id,
            String name,
            String desc,
            String source,
            String groupName
    ) {
    }

    public record AccessRoleDetailResponse(
            Long id,
            String name,
            String desc,
            List<AccessPermissionSummaryResponse> permissions,
            List<AccessUserMemberResponse> directUsers
    ) {
    }

    public record AccessPermissionSummaryResponse(
            Long id,
            String name,
            String friendlyName,
            String description
    ) {
    }

    public record AccessPermissionSourceResponse(
            String name,
            String friendlyName,
            String source
    ) {
    }

    public static class UpdateUserGroupsRequest {
        private List<Long> groupIds;
        private boolean groupIdsSet;

        public List<Long> getGroupIds() {
            return groupIds;
        }

        public void setGroupIds(List<Long> groupIds) {
            this.groupIdsSet = true;
            this.groupIds = groupIds;
        }

        public List<Long> groupIdsOrEmpty() {
            if (groupIdsSet && groupIds == null) {
                throw new IllegalArgumentException("groupIds must not be null");
            }
            return groupIds != null ? groupIds : Collections.emptyList();
        }
    }

    public static class UpdateRolePermissionsRequest {
        private List<Long> permissionIds;
        private boolean permissionIdsSet;

        public List<Long> getPermissionIds() {
            return permissionIds;
        }

        public void setPermissionIds(List<Long> permissionIds) {
            this.permissionIdsSet = true;
            this.permissionIds = permissionIds;
        }

        public List<Long> permissionIdsOrEmpty() {
            if (permissionIdsSet && permissionIds == null) {
                throw new IllegalArgumentException("permissionIds must not be null");
            }
            return permissionIds != null ? permissionIds : Collections.emptyList();
        }
    }

    public static class AccessRoleAssignmentsRequest {
        private List<AccessRoleAssignmentRequest> roleAssignments;
        private List<Long> roleIds;
        private boolean roleIdsSet;

        public List<AccessRoleAssignmentRequest> getRoleAssignments() {
            return roleAssignments;
        }

        public void setRoleAssignments(List<AccessRoleAssignmentRequest> roleAssignments) {
            this.roleAssignments = roleAssignments;
        }

        public List<Long> getRoleIds() {
            return roleIds;
        }

        public void setRoleIds(List<Long> roleIds) {
            this.roleIdsSet = true;
            this.roleIds = roleIds;
        }

        public List<Long> roleIdsOrEmpty() {
            if (roleIdsSet && roleIds == null) {
                throw new IllegalArgumentException("roleIds must not be null");
            }
            return roleIds != null ? roleIds : Collections.emptyList();
        }
    }

    public static class AccessRoleAssignmentRequest {
        private Long roleId;
        private List<String> crudPermissions;
        private boolean crudPermissionsSet;
        private List<Long> extraPermissionIds;

        public Long getRoleId() {
            return roleId;
        }

        public void setRoleId(Long roleId) {
            this.roleId = roleId;
        }

        public List<String> getCrudPermissions() {
            return crudPermissions;
        }

        public void setCrudPermissions(List<String> crudPermissions) {
            this.crudPermissionsSet = true;
            this.crudPermissions = crudPermissions;
        }

        public List<String> crudPermissionsOrDefault() {
            if (crudPermissionsSet && crudPermissions == null) {
                throw new IllegalArgumentException("crudPermissions must not be null");
            }
            return crudPermissions != null ? crudPermissions : List.of("READ");
        }

        public List<Long> getExtraPermissionIds() {
            return extraPermissionIds;
        }

        public void setExtraPermissionIds(List<Long> extraPermissionIds) {
            this.extraPermissionIds = extraPermissionIds;
        }

        public List<Long> extraPermissionIdsOrEmpty() {
            return extraPermissionIds != null ? extraPermissionIds : Collections.emptyList();
        }
    }
}
